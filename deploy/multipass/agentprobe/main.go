// Command agentprobe is an adversarial test client for the privileged agent's
// unix socket. It sends a single RPC frame (arbitrary op + JSON data +
// idempotency id, or a raw/oversized byte frame) and prints the response as
// compact JSON.
//
// It exists so the security suite can attack the agent boundary the way a
// compromised control plane would — real socket, real framing, real
// dispatcher and validation — instead of calling internal Go functions. Run
// it as the panel user to test validation; run it as a non-panel user to test
// the SO_PEERCRED gate.
//
// Exit codes: 0 = got a decoded response (inspect .ok / .error); 3 = transport
// error (dial refused, peer rejected, connection closed) — the expected
// outcome when an unauthorized uid connects.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	"github.com/nakroteck/nakpanel/internal/types"
)

func main() {
	socket := flag.String("socket", config.AgentSocket, "agent unix socket path")
	op := flag.String("op", "", "operation name (may be an unknown op)")
	data := flag.String("data", "{}", "raw JSON payload")
	id := flag.String("id", "", "idempotency id (random when empty)")
	mode := flag.String("mode", "envelope", "envelope | malformed | oversized")
	flag.Parse()

	requestID := strings.TrimSpace(*id)
	if requestID == "" {
		buf := make([]byte, 12)
		_, _ = rand.Read(buf)
		requestID = "probe-" + hex.EncodeToString(buf)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	switch *mode {
	case "malformed":
		// Not valid JSON — the server must reject the frame with no side effect.
		emit(rawFrame(ctx, *socket, []byte("this-is-not-json{\n")))
	case "oversized":
		// A syntactically valid envelope larger than MaxRequestBytes (1 MiB).
		pad := strings.Repeat("A", (1<<20)+4096)
		frame := fmt.Sprintf(`{"op":%q,"id":%q,"data":{"_pad":%q}}`+"\n", *op, requestID, pad)
		emit(rawFrame(ctx, *socket, []byte(frame)))
	default:
		client := agentclient.New(*socket)
		resp, err := client.Do(ctx, types.Request{
			Op:   *op,
			ID:   requestID,
			Data: json.RawMessage(*data),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "transport error: %v\n", err)
			emit(map[string]any{"transport_error": err.Error()})
			os.Exit(3)
		}
		emit(map[string]any{
			"id":    resp.ID,
			"ok":    resp.OK,
			"error": resp.Error,
			"data":  json.RawMessage(nonEmpty(resp.Data)),
		})
	}
}

// rawFrame dials the socket and writes the given bytes verbatim, then reads a
// single newline-terminated response line. Exits 3 on any transport failure.
func rawFrame(ctx context.Context, socket string, frame []byte) map[string]any {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "transport error: %v\n", err)
		os.Exit(3)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		fmt.Fprintf(os.Stderr, "transport error: %v\n", err)
		os.Exit(3)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 1<<20)).ReadString('\n')
	if err != nil && line == "" {
		return map[string]any{"transport_error": err.Error()}
	}
	var resp types.Response
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(line)), &resp); jsonErr != nil {
		return map[string]any{"raw_response": strings.TrimSpace(line)}
	}
	return map[string]any{"id": resp.ID, "ok": resp.OK, "error": resp.Error}
}

func nonEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

func emit(v any) {
	out, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(4)
	}
	fmt.Println(string(out))
}
