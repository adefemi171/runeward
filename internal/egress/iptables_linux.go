//go:build linux

package egress

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// SetupRedirect installs iptables rules that redirect outbound TCP to the
// transparent proxy on redirectPort, exempting the proxy's own uid, loopback,
// and DNS. Runs once from a privileged init container before the sandbox
// starts. Enforcement happens in the kernel, so an app can't opt out by
// ignoring HTTP(S)_PROXY.
func SetupRedirect(proxyUID, redirectPort int) error {
	uid := strconv.Itoa(proxyUID)
	port := strconv.Itoa(redirectPort)
	const chain = "RUNEWARD_OUT"

	steps := [][]string{
		{"-t", "nat", "-N", chain},
		// Don't redirect the proxy's own egress back to itself.
		{"-t", "nat", "-A", chain, "-m", "owner", "--uid-owner", uid, "-j", "RETURN"},
		{"-t", "nat", "-A", chain, "-o", "lo", "-j", "RETURN"},
		// Let DNS through so name resolution keeps working.
		{"-t", "nat", "-A", chain, "-p", "udp", "--dport", "53", "-j", "RETURN"},
		{"-t", "nat", "-A", chain, "-p", "tcp", "--dport", "53", "-j", "RETURN"},
		{"-t", "nat", "-A", chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", chain},
	}

	// Best-effort flush of any prior chain so re-runs don't stack rules.
	_ = run("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", chain)
	_ = run("iptables", "-t", "nat", "-F", chain)
	_ = run("iptables", "-t", "nat", "-X", chain)

	for _, args := range steps {
		if err := run("iptables", args...); err != nil {
			return fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
