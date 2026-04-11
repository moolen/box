package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

func StartTLS(ctx context.Context, cfg ProxyConfig) (*Server, error) {
	return start(ctx, cfg, func(s *Server, client net.Conn) {
		reader := bufio.NewReader(client)
		clientHello, sni, err := readClientHello(reader)
		if err != nil {
			return
		}

		if s.onEvent != nil {
			s.onEvent(Event{
				Protocol: "tls",
				Hostname: sni,
				SNI:      sni,
			})
		}

		s.forward(client, io.MultiReader(bytes.NewReader(clientHello), reader))
	})
}

func readClientHello(r *bufio.Reader) ([]byte, string, error) {
	recordHeader := make([]byte, 5)
	if _, err := io.ReadFull(r, recordHeader); err != nil {
		return nil, "", err
	}
	if recordHeader[0] != 0x16 {
		return nil, "", errors.New("not a tls handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(recordHeader[3:5]))
	if recordLen <= 0 {
		return nil, "", errors.New("empty tls record")
	}

	recordBody := make([]byte, recordLen)
	if _, err := io.ReadFull(r, recordBody); err != nil {
		return nil, "", err
	}

	record := append(recordHeader, recordBody...)
	sni := parseSNIFromClientHello(recordBody)
	return record, sni, nil
}

func parseSNIFromClientHello(handshake []byte) string {
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return ""
	}

	bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if bodyLen <= 0 || len(handshake) < 4+bodyLen {
		return ""
	}
	body := handshake[4 : 4+bodyLen]

	i := 0
	if len(body) < 2+32+1 {
		return ""
	}
	i += 2 + 32

	sessionIDLen := int(body[i])
	i++
	if len(body) < i+sessionIDLen+2 {
		return ""
	}
	i += sessionIDLen

	cipherLen := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2
	if len(body) < i+cipherLen+1 {
		return ""
	}
	i += cipherLen

	compressionLen := int(body[i])
	i++
	if len(body) < i+compressionLen+2 {
		return ""
	}
	i += compressionLen

	extensionsLen := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2
	if len(body) < i+extensionsLen {
		return ""
	}
	extensions := body[i : i+extensionsLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return ""
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		if extType != 0x0000 || len(extData) < 2 {
			continue
		}

		listLen := int(binary.BigEndian.Uint16(extData[:2]))
		names := extData[2:]
		if len(names) < listLen {
			return ""
		}
		names = names[:listLen]

		for len(names) >= 3 {
			nameType := names[0]
			nameLen := int(binary.BigEndian.Uint16(names[1:3]))
			names = names[3:]
			if len(names) < nameLen {
				return ""
			}
			name := names[:nameLen]
			names = names[nameLen:]
			if nameType == 0 {
				return string(name)
			}
		}
	}

	return ""
}
