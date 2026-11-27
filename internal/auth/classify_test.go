package auth

import (
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
)

func TestClassifyKerbCode(t *testing.T) {
	cases := []struct {
		name     string
		code     int32
		gotASRep bool
		want     Outcome
	}{
		{"principal unknown", errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, false, OutcomeNoSuchUser},
		{"preauth required", errorcode.KDC_ERR_PREAUTH_REQUIRED, false, OutcomeUserExists},
		{"etype nosupp", errorcode.KDC_ERR_ETYPE_NOSUPP, false, OutcomeUserExists},
		{"client revoked", errorcode.KDC_ERR_CLIENT_REVOKED, false, OutcomeLocked},
		{"skew", errorcode.KRB_AP_ERR_SKEW, false, OutcomeTimeSkew},
		{"as-rep roastable", 0, true, OutcomeUserNoPreauth},
		{"unknown code", 999, false, OutcomeError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyKerbCode(c.code, c.gotASRep); got != c.want {
				t.Fatalf("ClassifyKerbCode(%d,%v) = %v, want %v", c.code, c.gotASRep, got, c.want)
			}
		})
	}
}

func TestClassifyKerbErrSprayVsEnum(t *testing.T) {
	// The crucial issue-#3 property: in a SPRAY, a pre-auth failure is a bad
	// password (NOT a lockout); in ENUM, the same error proves the user exists.
	preauthFailed := errors.New("[Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: KRB Error: (24) KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid")
	if got := ClassifyKerbErr(preauthFailed, false); got != OutcomeBadPassword {
		t.Fatalf("spray preauth-failed = %v, want OutcomeBadPassword", got)
	}
	if got := ClassifyKerbErr(preauthFailed, true); got != OutcomeUserExists {
		t.Fatalf("enum preauth-failed = %v, want OutcomeUserExists", got)
	}

	cases := []struct {
		name string
		err  error
		enum bool
		want Outcome
	}{
		{"revoked spray", errors.New("KRB Error: (18) KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked"), false, OutcomeLocked},
		{"revoked enum", errors.New("KRB Error: (18) KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked"), true, OutcomeLocked},
		{"principal unknown enum", errors.New("KRB Error: (6) KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found"), true, OutcomeNoSuchUser},
		{"skew spray", errors.New("KRB Error: (37) KRB_AP_ERR_SKEW Clock skew too great"), false, OutcomeTimeSkew},
		{"network", errors.New("AS Exchange Error: failed sending AS_REQ to KDC: failed to communicate with KDC 10.0.0.1"), false, OutcomeNetworkError},
		{"key expired spray = creds valid", errors.New("KRB Error: (23) KDC_ERR_KEY_EXPIRED Password has expired"), false, OutcomePasswordMustChange},
		{"policy enum = smartcard", errors.New("AS Exchange Error: kerberos error response from KDC: KRB Error: (12) KDC_ERR_POLICY KDC policy rejects request"), true, OutcomeSmartcardReq},
		{"etype nosupp enum", errors.New("AS Exchange Error: kerberos error response from KDC: KRB Error: (14) KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type"), true, OutcomeUserExists},
		{"spray generic failure", errors.New("some other kerberos error"), false, OutcomeBadPassword},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyKerbErr(c.err, c.enum); got != c.want {
				t.Fatalf("ClassifyKerbErr(%q,%v) = %v, want %v", c.err, c.enum, got, c.want)
			}
		})
	}
}

func TestClassifyLDAPErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"locked", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 775, v3839"), OutcomeLocked},
		{"bad password", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 52e, v3839"), OutcomeBadPassword},
		{"no such user", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 525, v3839"), OutcomeNoSuchUser},
		{"password expired = creds valid", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 532, v3839"), OutcomePasswordMustChange},
		{"must reset = creds valid", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 773, v3839"), OutcomePasswordMustChange},
		{"disabled = creds valid", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 533, v3839"), OutcomeAccountDisabled},
		{"expired account = creds valid", errors.New("LDAP Result Code 49: comment: AcceptSecurityContext error, data 701, v3839"), OutcomeAccountDisabled},
		{"generic", errors.New("some other bind error"), OutcomeBadPassword},
		{"nil = success", nil, OutcomeSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyLDAPErr(c.err); got != c.want {
				t.Fatalf("ClassifyLDAPErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestOutcomeCredentialsValid(t *testing.T) {
	valid := []Outcome{OutcomeSuccess, OutcomePasswordMustChange, OutcomeAccountDisabled}
	for _, o := range valid {
		if !o.CredentialsValid() {
			t.Fatalf("outcome %v should report credentials valid", o)
		}
	}
	for _, o := range []Outcome{OutcomeBadPassword, OutcomeLocked, OutcomeNoSuchUser, OutcomeUserExists} {
		if o.CredentialsValid() {
			t.Fatalf("outcome %v should NOT report credentials valid", o)
		}
	}
}
