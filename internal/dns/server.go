package dns

import (
	"context"
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
