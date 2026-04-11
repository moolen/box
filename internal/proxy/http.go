package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"gvisor-net/internal/config"
)

const maxHTTPHeaderBytes = 64 * 1024

type Event struct {
	Protocol string
	Hostname string
	Method   string
	Path     string

	Host string
	SNI  string
}

type ProxyConfig struct {
	ListenAddr      string
	Listen          func(network, address string) (net.Listener, error)
	DialContext     func(ctx context.Context, network, address string) (net.Conn, error)
	ResolveUpstream func(client net.Conn) (string, error)
	OnEvent         func(Event)
}

type Server struct {
	ln              net.Listener
	dialContext     func(ctx context.Context, network, address string) (net.Conn, error)
	dialCtx         context.Context
	dialCancel      context.CancelFunc
	resolveUpstream func(client net.Conn) (string, error)
	onEvent         func(Event)
	handleConn      func(*Server, net.Conn)

	closeOnce sync.Once
	wg        sync.WaitGroup
	connMu    sync.Mutex
	conns     map[net.Conn]struct{}
}

func StartHTTP(ctx context.Context, cfg ProxyConfig) (*Server, error) {
	return start(ctx, cfg, func(s *Server, client net.Conn) {
		reader := bufio.NewReader(client)

		head, err := readHTTPHead(reader)
		if err != nil {
			return
		}

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
		if err != nil {
			return
		}

		host := httpRequestHost(req)

		if s.onEvent != nil {
			s.onEvent(Event{
				Protocol: "http",
				Hostname: host,
				Method:   req.Method,
				Path:     httpRequestPath(req),
				Host:     host,
			})
		}

		upstreamAddr, err := s.resolveUpstreamAddr(client, host, defaultHTTPPort(req))
		if err != nil {
			return
		}

		if strings.EqualFold(req.Method, http.MethodConnect) {
			s.tunnelHTTPConnect(client, reader, upstreamAddr)
			return
		}

		rewrittenHead, err := rewriteHTTPRequestHead(req)
		if err != nil {
			return
		}
		s.forward(client, io.MultiReader(bytes.NewReader(rewrittenHead), reader), upstreamAddr)
	})
}

func TransparentListenerFactory(
	cfg config.TransparentProxyConfig,
	listen func(network, address string) (net.Listener, error),
) (httpListener, tlsListener net.Listener, err error) {
	if cfg.HTTPPort <= 0 {
		return nil, nil, errors.New("http port must be positive")
	}
	if cfg.TLSPort <= 0 {
		return nil, nil, errors.New("tls port must be positive")
	}

	if listen == nil {
		listen = net.Listen
	}

	httpListener, err = listen("tcp", ":"+strconv.Itoa(cfg.HTTPPort))
	if err != nil {
		return nil, nil, fmt.Errorf("listen http on port %d: %w", cfg.HTTPPort, err)
	}

	tlsListener, err = listen("tcp", ":"+strconv.Itoa(cfg.TLSPort))
	if err != nil {
		_ = httpListener.Close()
		return nil, nil, fmt.Errorf("listen tls on port %d: %w", cfg.TLSPort, err)
	}

	return httpListener, tlsListener, nil
}

func start(ctx context.Context, cfg ProxyConfig, handler func(*Server, net.Conn)) (*Server, error) {
	listen := cfg.Listen
	if listen == nil {
		listen = net.Listen
	}

	addr := strings.TrimSpace(cfg.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}

	ln, err := listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", addr, err)
	}

	dialContext := cfg.DialContext
	if dialContext == nil {
		dialer := net.Dialer{}
		dialContext = dialer.DialContext
	}

	s := &Server{
		ln:              ln,
		dialContext:     dialContext,
		dialCtx:         context.Background(),
		dialCancel:      func() {},
		resolveUpstream: cfg.ResolveUpstream,
		onEvent:         cfg.OnEvent,
		handleConn:      handler,
		conns:           make(map[net.Conn]struct{}),
	}
	s.dialCtx, s.dialCancel = context.WithCancel(s.dialCtx)

	s.wg.Add(1)
	go s.serve(ctx)
	return s, nil
}

func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.dialCancel()
		closeErr = s.ln.Close()
		s.closeAllConns()
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

	for {
		client, err := s.ln.Accept()
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

		s.trackConn(client)

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrackAndClose(c)
			s.handleConn(s, c)
		}(client)
	}
}

func (s *Server) forward(client net.Conn, clientReader io.Reader, upstreamAddr string) {
	upstream, err := s.dialContext(s.dialCtx, "tcp", upstreamAddr)
	if err != nil {
		return
	}
	s.trackConn(upstream)
	defer s.untrackAndClose(upstream)

	copyDone := make(chan struct{}, 2)
	go copyHalf(upstream, clientReader, copyDone)
	go copyHalf(client, upstream, copyDone)

	<-copyDone
	_ = client.Close()
	_ = upstream.Close()
	<-copyDone
}

func (s *Server) tunnelHTTPConnect(client net.Conn, clientReader io.Reader, upstreamAddr string) {
	upstream, err := s.dialContext(s.dialCtx, "tcp", upstreamAddr)
	if err != nil {
		return
	}
	s.trackConn(upstream)
	defer s.untrackAndClose(upstream)

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	copyDone := make(chan struct{}, 2)
	go copyHalf(upstream, clientReader, copyDone)
	go copyHalf(client, upstream, copyDone)

	<-copyDone
	_ = client.Close()
	_ = upstream.Close()
	<-copyDone
}

func (s *Server) resolveUpstreamAddr(client net.Conn, fallbackHost, defaultPort string) (string, error) {
	if s.resolveUpstream != nil {
		return s.resolveUpstream(client)
	}

	host := strings.TrimSpace(fallbackHost)
	if host == "" {
		return "", errors.New("upstream host is required")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	return net.JoinHostPort(host, defaultPort), nil
}

func copyHalf(dst io.Writer, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}

func (s *Server) trackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conns[conn] = struct{}{}
}

func (s *Server) untrackAndClose(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	s.connMu.Unlock()
	_ = conn.Close()
}

func (s *Server) closeAllConns() {
	s.connMu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connMu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func readHTTPHead(r *bufio.Reader) ([]byte, error) {
	var head []byte
	for len(head) < maxHTTPHeaderBytes {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		head = append(head, b)
		if bytes.HasSuffix(head, []byte("\r\n\r\n")) {
			return head, nil
		}
	}
	return nil, errors.New("http header too large")
}

func httpRequestHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if strings.TrimSpace(req.Host) != "" {
		return req.Host
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

func httpRequestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.URL.Path != "" {
		return req.URL.Path
	}
	return req.URL.Opaque
}

func defaultHTTPPort(req *http.Request) string {
	if req != nil && strings.EqualFold(req.Method, http.MethodConnect) {
		return "443"
	}
	return "80"
}

func rewriteHTTPRequestHead(req *http.Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("http request is required")
	}

	clone := new(http.Request)
	*clone = *req
	if req.URL != nil {
		urlCopy := *req.URL
		urlCopy.Scheme = ""
		urlCopy.Host = ""
		clone.URL = &urlCopy
	}
	clone.RequestURI = ""
	clone.Close = false

	var buf bytes.Buffer
	if err := clone.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
