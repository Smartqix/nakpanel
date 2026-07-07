package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/nakroteck/nakpanel/internal/types"
)

const MaxRequestBytes = 1 << 20

type Server struct {
	dispatcher     *Dispatcher
	allowedPeerUID int
}

type ServerOption func(*Server)

func WithAllowedPeerUID(uid uint32) ServerOption {
	return func(s *Server) {
		s.allowedPeerUID = int(uid)
	}
}

func NewServer(dispatcher *Dispatcher, options ...ServerOption) *Server {
	server := &Server{dispatcher: dispatcher, allowedPeerUID: -1}
	for _, option := range options {
		option(server)
	}
	return server
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept agent connection: %w", err)
		}

		go func() {
			if err := s.authorizePeer(conn); err != nil {
				_ = writeErrorResponse(conn, "unauthorized peer: "+err.Error())
				_ = conn.Close()
				return
			}
			_ = HandleConn(ctx, conn, s.dispatcher)
		}()
	}
}

func (s *Server) authorizePeer(conn net.Conn) error {
	if s.allowedPeerUID < 0 {
		return nil
	}
	uid, ok, err := peerUID(conn)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if !allowedPeerUIDMatches(uid, s.allowedPeerUID) {
		return fmt.Errorf("uid %d is not allowed", uid)
	}
	return nil
}

func allowedPeerUIDMatches(peerUID uint32, allowedUID int) bool {
	return allowedUID >= 0 && peerUID == uint32(allowedUID)
}

func HandleConn(ctx context.Context, conn net.Conn, dispatcher *Dispatcher) error {
	defer conn.Close()

	limited := &io.LimitedReader{R: conn, N: MaxRequestBytes + 1}
	var req types.Request
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		errMsg := "invalid request json"
		if limited.N <= 0 {
			errMsg = "request too large"
		} else if !errors.Is(err, io.EOF) {
			errMsg = "invalid request json: " + err.Error()
		}
		if encodeErr := writeErrorResponse(conn, errMsg); encodeErr != nil {
			return encodeErr
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		return nil
	}
	if limited.N <= 0 {
		return writeErrorResponse(conn, "request too large")
	}

	resp := dispatcher.Dispatch(ctx, req)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		return fmt.Errorf("write agent response: %w", err)
	}
	return nil
}

func writeErrorResponse(conn net.Conn, msg string) error {
	resp := types.Response{
		OK:    false,
		Error: msg,
	}
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		return fmt.Errorf("write error response: %w", err)
	}
	return nil
}
