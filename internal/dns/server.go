package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const defaultDNSPort = "1053"

type Config struct {
	ListenAddr string
	Upstreams  []string
	OnQuery    func(hostname string)
}

type Deps struct {
	Mode         string
	GatewayIP    string
	ListenPacket func(network, address string) (net.PacketConn, error)
	DialContext  func(ctx context.Context, network, address string) (net.Conn, error)
}

type Server struct {
	conn        net.PacketConn
	upstreams   []string
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	onQuery     func(hostname string)
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

func Start(ctx context.Context, cfg Config, deps Deps) (*Server, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("at least one dns upstream is required")
	}

	listenAddr, err := ResolveListenAddr(cfg.ListenAddr, deps.Mode, deps.GatewayIP)
	if err != nil {
		return nil, err
	}

	listenPacket := deps.ListenPacket
	if listenPacket == nil {
		listenPacket = net.ListenPacket
	}
	conn, err := listenPacket("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", listenAddr, err)
	}

	dialContext := deps.DialContext
	if dialContext == nil {
		dialer := net.Dialer{}
		dialContext = dialer.DialContext
	}

	s := &Server{
		conn:        conn,
		upstreams:   append([]string(nil), cfg.Upstreams...),
		dialContext: dialContext,
		onQuery:     cfg.OnQuery,
	}

	s.wg.Add(1)
	go s.serve(ctx)

	return s, nil
}

func ResolveListenAddr(bindAddr, mode, gatewayIP string) (string, error) {
	bindAddr = strings.TrimSpace(bindAddr)
	if bindAddr == "" {
		bindAddr = "auto"
	}

	if strings.EqualFold(mode, "monitor") {
		gatewayIP = strings.TrimSpace(gatewayIP)
		if gatewayIP == "" {
			return "", errors.New("gateway ip is required in monitor mode")
		}
		if strings.EqualFold(bindAddr, "auto") {
			return net.JoinHostPort(gatewayIP, defaultDNSPort), nil
		}

		_, port, err := net.SplitHostPort(bindAddr)
		if err != nil {
			return "", fmt.Errorf("parse dns bind addr %q: %w", bindAddr, err)
		}
		return net.JoinHostPort(gatewayIP, port), nil
	}

	if strings.EqualFold(bindAddr, "auto") {
		return "127.0.0.1:" + defaultDNSPort, nil
	}
	if _, _, err := net.SplitHostPort(bindAddr); err != nil {
		return "", fmt.Errorf("parse dns bind addr %q: %w", bindAddr, err)
	}
	return bindAddr, nil
}

func (s *Server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		closeErr = s.conn.Close()
		s.wg.Wait()
	})
	return closeErr
}

func (s *Server) serve(ctx context.Context) {
	defer s.wg.Done()

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		if s.onQuery != nil {
			hostname, _ := parseQueryHostname(query)
			s.onQuery(hostname)
		}

		s.wg.Add(1)
		go s.forwardOne(query, clientAddr)
	}
}

func (s *Server) forwardOne(query []byte, clientAddr net.Addr) {
	defer s.wg.Done()

	for _, upstream := range s.upstreams {
		response, err := s.queryUpstream(upstream, query)
		if err != nil {
			continue
		}
		_, _ = s.conn.WriteTo(response, clientAddr)
		return
	}
}

func (s *Server) queryUpstream(upstream string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := s.dialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	response := make([]byte, n)
	copy(response, buf[:n])
	return response, nil
}

func parseQueryHostname(query []byte) (string, bool) {
	if len(query) < 12 {
		return "", false
	}
	if binary.BigEndian.Uint16(query[4:6]) == 0 {
		return "", false
	}

	hostname, next, ok := parseDNSName(query, 12, 0)
	if !ok {
		return "", false
	}
	if next+4 > len(query) {
		return "", false
	}
	return hostname, true
}

func parseDNSName(msg []byte, off, depth int) (string, int, bool) {
	if depth > 8 {
		return "", 0, false
	}
	if off < 0 || off >= len(msg) {
		return "", 0, false
	}

	labels := make([]string, 0, 4)
	curr := off
	next := off
	jumped := false

	for {
		if curr >= len(msg) {
			return "", 0, false
		}

		n := msg[curr]
		if n == 0 {
			if !jumped {
				next = curr + 1
			}
			return strings.Join(labels, "."), next, true
		}

		if n&0xC0 == 0xC0 {
			if curr+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(n&0x3F)<<8 | int(msg[curr+1])
			label, _, ok := parseDNSName(msg, ptr, depth+1)
			if !ok {
				return "", 0, false
			}
			if label != "" {
				labels = append(labels, label)
			}
			if !jumped {
				next = curr + 2
			}
			return strings.Join(labels, "."), next, true
		}

		labelLen := int(n)
		if labelLen > 63 {
			return "", 0, false
		}
		curr++
		if curr+labelLen > len(msg) {
			return "", 0, false
		}

		labels = append(labels, string(msg[curr:curr+labelLen]))
		curr += labelLen
		if !jumped {
			next = curr
		}
	}
}
