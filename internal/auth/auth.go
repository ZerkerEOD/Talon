// Package auth performs the actual Kerberos and LDAP authentication attempts
// and user-enumeration probes, and classifies their results into a typed
// Outcome so callers never have to substring-match error strings.
package auth

import (
	"fmt"

	"github.com/fatih/color"
)

// Outcome is the typed classification of a single attempt.
type Outcome int

const (
	// OutcomeError is a transport/parse/other failure, not an auth verdict.
	OutcomeError Outcome = iota
	// OutcomeSuccess means the submitted credentials were valid.
	OutcomeSuccess
	// OutcomeBadPassword means pre-auth failed / invalid credentials.
	OutcomeBadPassword
	// OutcomeLocked means the account is locked/revoked (KDC CLIENT_REVOKED / LDAP 775).
	OutcomeLocked
	// OutcomeNoSuchUser means the principal does not exist (C_PRINCIPAL_UNKNOWN / LDAP 525).
	OutcomeNoSuchUser
	// OutcomeUserExists means the user is valid (enum: PREAUTH_REQUIRED / ETYPE_NOSUPP).
	OutcomeUserExists
	// OutcomeUserNoPreauth means the user is valid and does not require pre-auth (AS-REP roastable).
	OutcomeUserNoPreauth
	// OutcomeSmartcardReq means the user is valid but a smartcard is required (KDC_ERR_POLICY).
	OutcomeSmartcardReq
	// OutcomeDESOnly means the user is valid, DES-only, and does not require pre-auth.
	OutcomeDESOnly
	// OutcomePasswordMustChange means the password is CORRECT but must be changed/expired.
	OutcomePasswordMustChange
	// OutcomeAccountDisabled means the password is CORRECT but the account is disabled/expired.
	OutcomeAccountDisabled
	// OutcomeTimeSkew means the clock skew between client and KDC is too great.
	OutcomeTimeSkew
	// OutcomeNetworkError means the KDC/DC could not be reached.
	OutcomeNetworkError
)

// label returns the human-readable result text and whether it is a "positive"
// finding (printed green with "[+]") or negative (red "[-]").
func (o Outcome) label() (text string, positive bool) {
	switch o {
	case OutcomeSuccess:
		return "Success", true
	case OutcomeBadPassword:
		return "Failed", false
	case OutcomeLocked:
		return "User's Account Locked", false
	case OutcomeNoSuchUser:
		return "User Does Not Exist", false
	case OutcomeUserExists:
		return "User Exist", true
	case OutcomeUserNoPreauth:
		return "User Exist - But Does Not Require Preauth (AS-REP roastable)", true
	case OutcomeSmartcardReq:
		return "User Exist - But Smartcard is Required", true
	case OutcomeDESOnly:
		return "User Exist - But Only Allows Kerberos DES Encryption and Does Not Require Preauth", true
	case OutcomePasswordMustChange:
		return "Success - Credentials Valid but Password Must Change", true
	case OutcomeAccountDisabled:
		return "Credentials Valid but Account Disabled/Expired", true
	case OutcomeTimeSkew:
		return "Clock skew between you and the KDC is too great", false
	case OutcomeNetworkError:
		return "Network Error", false
	default:
		return "Error", false
	}
}

// CredentialsValid reports whether the outcome proves the submitted password
// was correct (useful credential finding).
func (o Outcome) CredentialsValid() bool {
	switch o {
	case OutcomeSuccess, OutcomePasswordMustChange, OutcomeAccountDisabled:
		return true
	default:
		return false
	}
}

// UserValid reports whether the outcome proves the user exists.
func (o Outcome) UserValid() bool {
	switch o {
	case OutcomeSuccess, OutcomeUserExists, OutcomeUserNoPreauth, OutcomeSmartcardReq,
		OutcomeDESOnly, OutcomePasswordMustChange, OutcomeAccountDisabled, OutcomeLocked:
		return true
	default:
		return false
	}
}

// AttemptResult is the structured result of one Login call.
type AttemptResult struct {
	Outcome  Outcome
	Service  string // "KERB" | "LDAP" | "KERB-ENUM"
	Host     string
	Domain   string
	User     string
	Password string // empty for enumeration
	// Credentialed reports whether this attempt submitted a credential and so
	// could have incremented the target's badPwdCount (spray + aggressive enum).
	// Safe enumeration sets this false.
	Credentialed bool
	Err          error
}

func (r AttemptResult) line(colored bool) string {
	text, positive := r.Outcome.label()
	sign := "[-] "
	if positive {
		sign = "[+] "
	}
	body := fmt.Sprintf("%s %s %s\\%s:%s = %s", sign, r.Host, r.Domain, r.User, r.Password, text)
	if !colored {
		return body
	}
	tint := color.RedString
	if positive {
		tint = color.GreenString
	}
	// Color the sign and the result text, matching Talon's original style.
	return fmt.Sprintf("%s %s %s\\%s:%s = %s", tint(sign), r.Host, r.Domain, r.User, r.Password, tint(text))
}

// Display returns the colored stdout line for this result.
func (r AttemptResult) Display() string { return r.line(true) }

// FileLine returns the plain (uncolored) line for the -O output file.
func (r AttemptResult) FileLine() string { return r.line(false) }

// Authenticator performs one authentication/enumeration attempt.
type Authenticator interface {
	Login() AttemptResult
}
