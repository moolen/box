package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"gvisor-net/internal/config"
	"gvisor-net/internal/policyd"
)

func startICMPObserver(ctx context.Context, req ICMPMonitorStartRequest) (Runner, error) {
	if req.OnEvent == nil {
		return nil, nil
	}
	if strings.TrimSpace(req.NetNS) == "" {
		return nil, errors.New("netns is required")
	}
	if strings.TrimSpace(req.Interface) == "" {
		return nil, errors.New("interface is required")
	}
	subnet, err := netip.ParsePrefix(strings.TrimSpace(req.SubnetCIDR))
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q: %w", req.SubnetCIDR, err)
	}

	fd, err := openICMPPacketSocket(req.Interface)
	if err != nil {
		return nil, err
	}

	observer := &icmpObserver{
		fd:      fd,
		done:    make(chan struct{}),
		onEvent: req.OnEvent,
		subnet:  subnet.Masked(),
		rules:   append([]config.NetworkPolicyRule(nil), req.Rules...),
	}
	go observer.run()
	go func() {
		<-ctx.Done()
		_ = observer.Stop()
	}()
	return observer, nil
}

type icmpObserver struct {
	fd       int
	done     chan struct{}
	stopOnce sync.Once
	onEvent  func(policyd.Event)
	subnet   netip.Prefix
	rules    []config.NetworkPolicyRule
	stopped  atomic.Bool
}

func (o *icmpObserver) Stop() error {
	if o == nil {
		return nil
	}
	o.stopOnce.Do(func() {
		o.stopped.Store(true)
		_ = unix.Close(o.fd)
	})
	<-o.done
	return nil
}

func (o *icmpObserver) run() {
	defer close(o.done)

	buf := make([]byte, 4096)
	pollFDs := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pollFDs, 500)
		if err != nil {
			if o.stopped.Load() {
				return
			}
			continue
		}
		if n == 0 {
			if o.stopped.Load() {
				return
			}
			continue
		}
		n, from, err := unix.Recvfrom(o.fd, buf, 0)
		if err != nil {
			if o.stopped.Load() {
				return
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return
		}
		if _, ok := from.(*unix.SockaddrLinklayer); !ok {
			continue
		}
		source, destination, icmpType, icmpCode, ok := parseObservedICMPv4Packet(buf[:n])
		if !ok {
			continue
		}
		if !o.subnet.Contains(source) {
			continue
		}

		decision := policyd.EvaluateICMP(destination, icmpType, icmpCode, o.rules, policyd.ModeObserve)
		typeCopy := icmpType
		codeCopy := icmpCode
		o.onEvent(policyd.Event{
			Type:        "icmp",
			Protocol:    "icmp",
			Destination: destination.String(),
			ICMPType:    &typeCopy,
			ICMPCode:    &codeCopy,
			Verdict:     decision.Verdict,
			Reason:      decision.Reason,
		})
	}
}

func openICMPPacketSocket(ifaceName string) (int, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return -1, fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	protocol := int(htons(uint16(unix.ETH_P_IP)))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return -1, fmt.Errorf("open packet socket: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("set packet socket nonblocking: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(uint16(unix.ETH_P_IP)),
		Ifindex:  iface.Index,
	}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind packet socket: %w", err)
	}
	return fd, nil
}

func parseObservedICMPv4Packet(frame []byte) (netip.Addr, netip.Addr, int, int, bool) {
	const ethernetHeaderLen = 14
	const minIPv4HeaderLen = 20
	const minICMPHeaderLen = 8

	if len(frame) < ethernetHeaderLen+minIPv4HeaderLen+minICMPHeaderLen {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != uint16(unix.ETH_P_IP) {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}

	ip := frame[ethernetHeaderLen:]
	if version := ip[0] >> 4; version != 4 {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < minIPv4HeaderLen || len(ip) < ihl+minICMPHeaderLen {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	if ip[9] != 1 {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}

	source, ok := netip.AddrFromSlice(ip[12:16])
	if !ok {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	destination, ok := netip.AddrFromSlice(ip[16:20])
	if !ok {
		return netip.Addr{}, netip.Addr{}, 0, 0, false
	}
	icmp := ip[ihl:]
	return source, destination, int(icmp[0]), int(icmp[1]), true
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
