package auth

import (
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

// EnumMode selects how a KERB attempt behaves.
type EnumMode int

const (
	// EnumOff performs a normal password-guess (spray).
	EnumOff EnumMode = iota
	// EnumSafe performs pre-auth-less enumeration (never submits a password,
	// never increments badPwdCount).
	EnumSafe
	// EnumAggressive performs enumeration via a real pre-auth exchange (richer
	// signal, but CAN lock accounts).
	EnumAggressive
)

// KERB is a Kerberos authentication/enumeration attempt.
type KERB struct {
	Host     string
	Domain   string
	User     string
	Password string
	Mode     EnumMode
}

// Login performs the attempt and returns a classified result.
func (k KERB) Login() AttemptResult {
	if k.Mode == EnumSafe {
		return k.loginEnumSafe()
	}
	return k.loginClient()
}

// minimalKrb5Conf builds a minimal krb5.conf pointing at a single KDC.
func minimalKrb5Conf(domain, host string) string {
	realm := strings.ToUpper(domain)
	return "[libdefaults]\n" +
		" default_realm = " + realm + "\n" +
		" dns_lookup_realm = false\n" +
		" dns_lookup_kdc = false\n" +
		"[realms]\n" +
		" " + realm + " = {\n" +
		"  kdc = " + host + ":88\n" +
		" }\n"
}

func (k KERB) result(oc Outcome, credentialed bool, err error) AttemptResult {
	return AttemptResult{
		Outcome:      oc,
		Service:      "KERB",
		Host:         k.Host,
		Domain:       k.Domain,
		User:         k.User,
		Password:     k.Password,
		Credentialed: credentialed,
		Err:          err,
	}
}

// loginClient handles spray (EnumOff) and aggressive enum (EnumAggressive).
// Both drive gokrb5's client.Login(), which performs a real pre-auth exchange
// and therefore consumes a badPwdCount attempt on the target.
func (k KERB) loginClient() AttemptResult {
	cfg, err := config.NewFromString(minimalKrb5Conf(k.Domain, k.Host))
	if err != nil {
		return k.result(OutcomeError, false, err)
	}
	aggressive := k.Mode == EnumAggressive
	if aggressive {
		// Request an obsolete etype so a DC that has DES disabled rejects the
		// request up front (KDC_ERR_ETYPE_NOSUPP) before the password check.
		cfg.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.DES_CBC_CRC)}
	}
	cl := client.NewWithPassword(k.User, strings.ToUpper(k.Domain), k.Password, cfg, client.DisablePAFXFAST(true))
	err = cl.Login()
	if err == nil {
		return k.result(OutcomeSuccess, true, nil)
	}
	return k.result(ClassifyKerbErr(err, aggressive), true, err)
}
