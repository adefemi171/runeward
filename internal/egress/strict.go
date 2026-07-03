package egress

// Constants shared between the Kubernetes backend and the runeward-egress
// binary for strict (L3) enforcement.
const (
	// StrictProxyUID is the uid the transparent proxy runs as; iptables
	// exempts it so the proxy's upstream traffic isn't redirected back to
	// itself. The sandbox must run as a different uid to be intercepted.
	StrictProxyUID = 1337

	// StrictRedirectPort is the proxy's listen port and the iptables REDIRECT target.
	StrictRedirectPort = 15001
)
