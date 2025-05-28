package iptables

import (
	"context"
	"fmt"
	"net"
	"os/exec"
)

// IPTablesResponder implements Responder via iptables.
type IPTablesResponder struct {
	Chain string
}

func New(chain string) *IPTablesResponder {
	return &IPTablesResponder{Chain: chain}
}

func (r *IPTablesResponder) Block(ctx context.Context, ip net.IP) error {
	cmd := exec.CommandContext(ctx, "iptables", "-I", r.Chain, "1", "-s", ip.String(), "-j", "DROP")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables block failed: %s", out)
	}
	return nil
}
func (r *IPTablesResponder) Unblock(ctx context.Context, ip net.IP) error {
	cmd := exec.CommandContext(ctx, "iptables", "-D", r.Chain, "-s", ip.String(), "-j", "DROP")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables unblock failed: %s", out)
	}
	return nil
}
