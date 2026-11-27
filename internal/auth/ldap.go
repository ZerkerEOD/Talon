package auth

import (
	"crypto/tls"
	"net"

	"github.com/go-ldap/ldap/v3"
)

// LDAP is an LDAPS authentication attempt.
type LDAP struct {
	Host     string
	Domain   string
	User     string
	Password string
}

func (l LDAP) result(oc Outcome, err error) AttemptResult {
	return AttemptResult{
		Outcome:      oc,
		Service:      "LDAP",
		Host:         l.Host,
		Domain:       l.Domain,
		User:         l.User,
		Password:     l.Password,
		Credentialed: true,
		Err:          err,
	}
}

// Login performs an LDAPS simple bind. TLS verification is intentionally
// skipped: engagements routinely target DCs with self-signed certificates
// (accepted residual risk, documented in the design).
func (l LDAP) Login() AttemptResult {
	conn, err := ldap.DialURL(
		"ldaps://"+net.JoinHostPort(l.Host, "636"),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec // see doc comment
	)
	if err != nil {
		return l.result(OutcomeNetworkError, err)
	}
	defer conn.Close()

	if err := conn.Bind(l.User+"@"+l.Domain, l.Password); err != nil {
		return l.result(ClassifyLDAPErr(err), err)
	}
	return l.result(OutcomeSuccess, nil)
}
