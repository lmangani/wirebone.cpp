// Two tsnet nodes join a wirebone coordinator and exchange a byte over 100.x.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: tsnet_two_node <control_url> <authkey>\n")
		os.Exit(2)
	}
	control := os.Args[1]
	auth := os.Args[2]
	root, err := os.MkdirTemp("", "wirebone-tsnet-")
	must(err)
	defer os.RemoveAll(root)

	s1 := &tsnet.Server{
		Dir:        filepath.Join(root, "n1"),
		Hostname:   "node-one",
		ControlURL: control,
		AuthKey:    auth,
		Ephemeral:  true,
	}
	s2 := &tsnet.Server{
		Dir:        filepath.Join(root, "n2"),
		Hostname:   "node-two",
		ControlURL: control,
		AuthKey:    auth,
		Ephemeral:  true,
	}
	defer s1.Close()
	defer s2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if err := s1.Start(); err != nil {
		must(err)
	}
	lc1, err := s1.LocalClient()
	must(err)
	watcher, err := lc1.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialNetMap)
	must(err)
	for {
		n, err := watcher.Next()
		if err != nil {
			must(fmt.Errorf("watch: %w", err))
		}
		if n.ErrMessage != nil {
			fmt.Println("err", *n.ErrMessage)
		}
		if n.State != nil {
			fmt.Println("state", *n.State)
		}
		if n.NetMap != nil {
			fmt.Println("netmap self", n.NetMap.SelfNode.Addresses())
			break
		}
	}
	st1, err := s1.Up(ctx)
	must(err)
	st2, err := s2.Up(ctx)
	must(err)
	fmt.Println("n1", st1.TailscaleIPs)
	fmt.Println("n2", st2.TailscaleIPs)
	if len(st1.TailscaleIPs) == 0 || len(st2.TailscaleIPs) == 0 {
		panic("missing tailscale IPs")
	}

	ln, err := s1.Listen("tcp", ":7070")
	must(err)
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "pong")
	}))

	// Prefer MagicDNS hostname; fall back to 100.x.
	targets := []string{
		"node-one.wirebone.local:7070",
		net.JoinHostPort(st1.TailscaleIPs[0].String(), "7070"),
	}
	var last error
	for _, dst := range targets {
		c, err := s2.Dial(ctx, "tcp", dst)
		if err != nil {
			last = err
			continue
		}
		fmt.Fprintf(c, "GET / HTTP/1.0\r\n\r\n")
		body, err := io.ReadAll(c)
		c.Close()
		must(err)
		if !strings.Contains(string(body), "pong") {
			last = fmt.Errorf("unexpected body %q via %s", body, dst)
			continue
		}
		fmt.Println("ok via", dst)
		return
	}
	panic(last)
}
