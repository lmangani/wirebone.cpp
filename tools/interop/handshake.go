// Verifies /key + TS2021 Noise handshake against a running wirebone coordinator.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"tailscale.com/control/controlhttp"
	"tailscale.com/types/key"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: handshake_test <control_url>\n")
		os.Exit(2)
	}
	base := os.Args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := http.Get(base + "/key?v=131")
	if err != nil {
		panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		panic(err)
	}
	var keys struct {
		PublicKey key.MachinePublic `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &keys); err != nil {
		panic(err)
	}
	if keys.PublicKey.IsZero() {
		panic("empty publicKey")
	}

	d := &controlhttp.Dialer{
		Hostname:        "127.0.0.1",
		HTTPPort:        "8080",
		MachineKey:      key.NewMachine(),
		ControlKey:      keys.PublicKey,
		ProtocolVersion: 131,
	}
	// Honor explicit host:port from the control URL if present.
	u := base
	if len(u) > 7 && u[:7] == "http://" {
		hostport := u[7:]
		host, port := hostport, "80"
		for i := 0; i < len(hostport); i++ {
			if hostport[i] == ':' {
				host = hostport[:i]
				port = hostport[i+1:]
				break
			}
		}
		d.Hostname = host
		d.HTTPPort = port
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		panic(err)
	}
	conn.Close()
	fmt.Println("handshake ok", keys.PublicKey)
}
