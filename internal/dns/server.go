package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const defaultDNSPort = "53"

type Config struct {
	ListenAddr string
	Upstreams  []string
	OnQuery    func(hostname string)
	AllowQuery func(hostname string) bool
	OnResolved func(Resolution)
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
	mode        string
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	onQuery     func(hostname string)
	allowQuery  func(hostname string) bool
	onResolved  func(Resolution)
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

type Resolution struct {
	Hostname string
	IPs      []netip.Addr
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
		mode:        strings.ToLower(strings.TrimSpace(deps.Mode)),
		dialContext: dialContext,
		onQuery:     cfg.OnQuery,
		allowQuery:  cfg.AllowQuery,
		onResolved:  cfg.OnResolved,
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

	if strings.EqualFold(mode, "monitor") || strings.EqualFold(mode, "enforce") {
		gatewayIP = strings.TrimSpace(gatewayIP)
		if gatewayIP == "" {
			return "", fmt.Errorf("gateway ip is required in %s mode", strings.ToLower(mode))
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

		hostname, hostnameOK := parseQueryHostname(query)
		if s.onQuery != nil && hostnameOK {
			s.onQuery(hostname)
		}
		if s.allowQuery != nil {
			allowed := false
			if hostnameOK {
				allowed = s.allowQuery(hostname)
			}
			if !allowed {
				if response, ok := buildNXDOMAINResponse(query); ok {
					_, _ = s.conn.WriteTo(response, clientAddr)
				}
				continue
			}
		}
		if s.mode == "enforce" {
			if qtype, ok := parseQueryType(query); ok && qtype == 28 {
				if response, ok := buildEmptySuccessResponse(query); ok {
					_, _ = s.conn.WriteTo(response, clientAddr)
				}
				continue
			}
		}

		s.wg.Add(1)
		go s.forwardOne(query, hostname, hostnameOK, clientAddr)
	}
}

func (s *Server) forwardOne(query []byte, hostname string, hostnameOK bool, clientAddr net.Addr) {
	defer s.wg.Done()

	for _, upstream := range s.upstreams {
		response, err := s.queryUpstream(upstream, query)
		if err != nil {
			continue
		}
		if s.onResolved != nil && hostnameOK {
			s.onResolved(Resolution{
				Hostname: hostname,
				IPs:      parseResponseIPs(response),
			})
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
	hostname, _, ok := parseQueryQuestion(query)
	return hostname, ok
}

func parseQueryType(query []byte) (uint16, bool) {
	_, qtype, ok := parseQueryQuestion(query)
	return qtype, ok
}

func parseQueryQuestion(query []byte) (string, uint16, bool) {
	if len(query) < 12 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(query[4:6]) == 0 {
		return "", 0, false
	}

	hostname, next, ok := parseDNSName(query, 12, 0)
	if !ok {
		return "", 0, false
	}
	if next+4 > len(query) {
		return "", 0, false
	}
	return hostname, binary.BigEndian.Uint16(query[next : next+2]), true
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

	for {
		if curr >= len(msg) {
			return "", 0, false
		}

		n := msg[curr]
		if n == 0 {
			return strings.Join(labels, "."), curr + 1, true
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
			return strings.Join(labels, "."), curr + 2, true
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
	}
}

func buildNXDOMAINResponse(query []byte) ([]byte, bool) {
	if len(query) < 12 {
		return nil, false
	}

	response := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000
	flags &^= 0x0200
	flags &^= 0x000f
	flags |= 0x0003
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response, true
}

func buildEmptySuccessResponse(query []byte) ([]byte, bool) {
	if len(query) < 12 {
		return nil, false
	}

	response := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000
	flags &^= 0x0200
	flags &^= 0x000f
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response, true
}

func parseResponseIPs(response []byte) []netip.Addr {
	if len(response) < 12 {
		return nil
	}

	questions := int(binary.BigEndian.Uint16(response[4:6]))
	answers := int(binary.BigEndian.Uint16(response[6:8]))
	offset := 12
	for i := 0; i < questions; i++ {
		_, next, ok := parseDNSName(response, offset, 0)
		if !ok || next+4 > len(response) {
			return nil
		}
		offset = next + 4
	}

	ips := make([]netip.Addr, 0, answers)
	for i := 0; i < answers; i++ {
		_, next, ok := parseDNSName(response, offset, 0)
		if !ok || next+10 > len(response) {
			return ips
		}
		recordType := binary.BigEndian.Uint16(response[next : next+2])
		dataLen := int(binary.BigEndian.Uint16(response[next+8 : next+10]))
		dataStart := next + 10
		dataEnd := dataStart + dataLen
		if dataEnd > len(response) {
			return ips
		}

		switch recordType {
		case 1, 28:
			if addr, ok := netip.AddrFromSlice(response[dataStart:dataEnd]); ok {
				ips = append(ips, addr.Unmap())
			}
		}

		offset = dataEnd
	}
	return ips
}
