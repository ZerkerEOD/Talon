package auth

import (
	"strings"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
)

// ClassifyKerbCode maps a KDC error code (read directly from a KRBError on the
// safe enumeration path) to an Outcome. gotASRep is true when the KDC returned
// a valid AS-REP instead of an error (the user exists and does not require
// pre-authentication — i.e. AS-REP roastable).
func ClassifyKerbCode(code int32, gotASRep bool) Outcome {
	if gotASRep {
		return OutcomeUserNoPreauth
	}
	switch code {
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return OutcomeNoSuchUser
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return OutcomeUserExists
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		return OutcomeLocked
	case errorcode.KRB_AP_ERR_SKEW:
		return OutcomeTimeSkew
	case errorcode.KDC_ERR_ETYPE_NOSUPP:
		// Principal was looked up before etype negotiation, so the user exists.
		return OutcomeUserExists
	default:
		return OutcomeError
	}
}

// ClassifyKerbErr maps a gokrb5 client Login() error (whose typed KRBError has
// been flattened into the error string) to an Outcome. The same KDC error means
// different things depending on mode: during enumeration a PREAUTH_FAILED proves
// the user exists, while during a spray it means a bad password.
func ClassifyKerbErr(err error, enum bool) Outcome {
	if err == nil {
		return OutcomeSuccess
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "failed to communicate with KDC"),
		strings.Contains(s, "failed sending AS_REQ"):
		return OutcomeNetworkError
	case strings.Contains(s, "KRB_AP_ERR_SKEW"):
		return OutcomeTimeSkew
	case strings.Contains(s, "KDC_ERR_CLIENT_REVOKED"):
		return OutcomeLocked
	case strings.Contains(s, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return OutcomeNoSuchUser
	case strings.Contains(s, "KDC_ERR_KEY_EXPIRED"):
		// Password is correct but expired.
		return OutcomePasswordMustChange
	}

	if enum {
		switch {
		case strings.Contains(s, "KDC_ERR_PREAUTH_FAILED"):
			return OutcomeUserExists
		case strings.Contains(s, "(12) KDC_ERR_POLICY"):
			return OutcomeSmartcardReq
		case strings.Contains(s, "(14) KDC_ERR_ETYPE_NOSUPP"):
			return OutcomeUserExists
		case strings.Contains(s, "integrity checksum incorrect"):
			return OutcomeDESOnly
		case strings.Contains(s, "integrity verification failed"):
			return OutcomeUserNoPreauth
		case strings.Contains(s, "KDC_ERR_PREAUTH_REQUIRED"):
			return OutcomeUserExists
		default:
			return OutcomeError
		}
	}

	// Spray mode: a pre-auth failure is a bad password; anything else unknown
	// is treated as a (non-fatal) failure.
	return OutcomeBadPassword
}

// ClassifyLDAPErr maps an LDAP bind error to an Outcome. Windows AD surfaces the
// reason in the AcceptSecurityContext "data NNN" sub-code; several of these mean
// the password was CORRECT (expired/disabled/must-change) and would otherwise be
// hidden as a plain failure.
func ClassifyLDAPErr(err error) Outcome {
	if err == nil {
		return OutcomeSuccess
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "data 775"):
		return OutcomeLocked
	case strings.Contains(s, "data 525"):
		return OutcomeNoSuchUser
	case strings.Contains(s, "data 532"), strings.Contains(s, "data 773"):
		// Password expired / user must reset password — password is correct.
		return OutcomePasswordMustChange
	case strings.Contains(s, "data 533"), strings.Contains(s, "data 701"):
		// Account disabled / account expired — password is correct.
		return OutcomeAccountDisabled
	case strings.Contains(s, "data 52e"):
		return OutcomeBadPassword
	default:
		return OutcomeBadPassword
	}
}
