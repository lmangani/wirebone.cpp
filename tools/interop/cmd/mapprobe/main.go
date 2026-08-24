package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

func main() {
	base := os.Args[1]
	auth := os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := http.Get(base + "/key?v=131")
	if err != nil {
		panic(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var keys tailcfg.OverTLSPublicKeyResponse
	if err := json.Unmarshal(raw, &keys); err != nil {
		panic(err)
	}

	host, port := "127.0.0.1", "18080"
	if len(base) > 7 {
		hp := base[7:]
		for i := 0; i < len(hp); i++ {
			if hp[i] == ':' {
				host, port = hp[:i], hp[i+1:]
				break
			}
		}
	}
	d := &controlhttp.Dialer{
		Hostname:        host,
		HTTPPort:        port,
		MachineKey:      key.NewMachine(),
		ControlKey:      keys.PublicKey,
		ProtocolVersion: 131,
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("noise ok")

	tr := &http2.Transport{AllowHTTP: true}
	h2c, err := tr.NewClientConn(conn)
	if err != nil {
		panic(err)
	}

	node := key.NewNode()
	reg := tailcfg.RegisterRequest{
		Version: 131,
		NodeKey: node.Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: auth},
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "probe",
		},
	}
	body, _ := json.Marshal(reg)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://wirebone/machine/register", bytes.NewReader(body))
	res, err := h2c.RoundTrip(req)
	if err != nil {
		panic(fmt.Errorf("register: %w", err))
	}
	rb, _ := io.ReadAll(res.Body)
	res.Body.Close()
	fmt.Println("register", res.Status, string(rb))

	mr := tailcfg.MapRequest{
		Version:   131,
		Compress:  "zstd",
		KeepAlive: true,
		NodeKey:   node.Public(),
		Stream:    true,
		Hostinfo:  &tailcfg.Hostinfo{Hostname: "probe"},
	}
	body, _ = json.Marshal(mr)
	req, _ = http.NewRequestWithContext(ctx, "POST", "https://wirebone/machine/map", bytes.NewReader(body))
	res, err = h2c.RoundTrip(req)
	if err != nil {
		panic(fmt.Errorf("map: %w", err))
	}
	mb, err := io.ReadAll(res.Body)
	res.Body.Close()
	fmt.Printf("map status=%s n=%d err=%v head=%x\n", res.Status, len(mb), err, prefix(mb, 16))
	if len(mb) >= 4 {
		n := int(mb[0]) | int(mb[1])<<8 | int(mb[2])<<16 | int(mb[3])<<24
		fmt.Println("len prefix", n, "rest", len(mb)-4)
		if n > 0 && n <= len(mb)-4 {
			dec, err := zstdframe.AppendDecode(nil, mb[4:4+n])
			fmt.Println("zstd", err, "json", len(dec))
			if err == nil {
				fmt.Println(string(dec[:min(200, len(dec))]))
			}
		}
	}
}

func prefix(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
