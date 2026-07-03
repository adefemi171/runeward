// Package egress implements the forward proxy that constrains sandbox network
// traffic. Sandboxes are pointed at it via HTTP(S)_PROXY, and it only permits
// connections allowed by a [Policy]. Stdlib only.
package egress

import (
	"encoding/json"
	"net"
	"os"
	"strings"
)

// Rule is a single allow/deny entry in a [Policy]. Set exactly one of
// Hostname or CIDR.
type Rule struct {
	// Verdict is "allow" or "deny"; anything but "allow" denies.
	Verdict string `json:"verdict"`
	// Hostname matches exactly or by a leading "*." wildcard.
	Hostname string `json:"hostname"`
	// CIDR matches a destination IP (e.g. "10.0.0.0/8").
	CIDR string `json:"cidr"`
}

// Policy is an ordered list of [Rule]s; the first match wins, otherwise
// Default applies.
type Policy struct {
	// Default is "allow" or "deny"; empty means "allow".
	Default string `json:"default"`
	Rules   []Rule `json:"rules"`
}

// verdictAllows reports whether a verdict permits the connection. Only
// "allow" (case-insensitive) permits; everything else, including "", denies.
func verdictAllows(verdict string) bool {
	return strings.EqualFold(strings.TrimSpace(verdict), "allow")
}

// defaultAllows is the fallback when no rule matches; empty means allow.
func (p Policy) defaultAllows() bool {
	if strings.TrimSpace(p.Default) == "" {
		return true
	}
	return verdictAllows(p.Default)
}

// hostnameMatches reports whether pattern matches host, case-insensitively.
// A "*." pattern matches subdomains at any depth but not the bare domain;
// anything else matches by equality.
func hostnameMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" {
		return false
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		// Require a label before the suffix so the bare domain doesn't match.
		return strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
	}
	return pattern == host
}

// Allow reports whether host is permitted. Only Hostname rules are
// considered; first match decides, otherwise Default applies.
func (p Policy) Allow(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, r := range p.Rules {
		if r.Hostname == "" {
			continue
		}
		if hostnameMatches(r.Hostname, host) {
			return verdictAllows(r.Verdict)
		}
	}
	return p.defaultAllows()
}

// AllowAddr reports whether the destination "host:port" is permitted. The
// host is checked against Hostname rules, and against CIDR rules when it
// parses as an IP; first match decides, otherwise Default applies.
func (p Policy) AllowAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port; treat the whole value as the host.
		host = hostport
	}
	host = strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(host)

	for _, r := range p.Rules {
		if r.Hostname != "" && hostnameMatches(r.Hostname, host) {
			return verdictAllows(r.Verdict)
		}
		if r.CIDR != "" && ip != nil {
			if _, network, err := net.ParseCIDR(r.CIDR); err == nil && network.Contains(ip) {
				return verdictAllows(r.Verdict)
			}
		}
	}
	return p.defaultAllows()
}

// LoadPolicy reads and decodes a JSON [Policy] from the file at path.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}
