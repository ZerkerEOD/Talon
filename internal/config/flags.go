// Package config defines Talon's command-line options and a small debug helper.
package config

import (
	"flag"
	"fmt"
	"os"
)

// Options holds all parsed command-line options.
type Options struct {
	Host     string
	Hostfile string
	Domain   string
	User     string
	Userfile string
	Passfile string
	Pass     string
	OutFile  string

	// Lockout is the account-lockout observation window in minutes (pacing).
	Lockout float64
	// Attempts is the number of password passes allowed before a mandatory
	// Lockout-length sleep (pacing across the lockout window).
	Attempts float64
	// LockErr is the number of distinct observed lockouts that trips the
	// stop-and-prompt detector.
	LockErr float64
	// Sleep is the delay between individual attempts, in seconds.
	Sleep float64
	// Threshold is the AD account-lockout threshold (badPwdCount limit). When
	// > 0, Talon stops spraying a user one attempt short of it. 0 = unknown,
	// in which case the run loop applies a conservative per-user budget.
	Threshold int

	Enum       bool // -E: safe (pre-auth-less) user enumeration
	Aggressive bool // -Eagg: aggressive (pre-auth) enumeration; implies Enum
	Kerb       bool // -K: Kerberos only
	LDAP       bool // -L: LDAP only
	Debug      bool // -debug
	Verbose    bool // -v: live running tally
}

var debugging bool

// Parse parses os.Args and returns the populated Options.
func Parse() *Options {
	host := flag.String("H", "", "Domain controller to connect to")
	hostfile := flag.String("Hostfile", "", "File containing the list of domain controllers to connect to")
	domain := flag.String("D", "", "Fully qualified domain to use")
	user := flag.String("U", "", "Username to authenticate as")
	userfile := flag.String("Userfile", "", "File containing the list of usernames")
	passfile := flag.String("Passfile", "", "File containing the list of passwords")
	lockout := flag.Float64("Lockout", 60, "Account lockout period in minutes")
	attempts := flag.Float64("A", 3, "Password passes allowed before a mandatory lockout-period sleep")
	pass := flag.String("P", "", "Password to use")
	outFile := flag.String("O", "", "File to append the results to")
	sleep := flag.Float64("sleep", .5, "Time in between attempts (seconds)")
	threshold := flag.Int("Threshold", 0, "AD account-lockout threshold (badPwdCount limit); stop one attempt short. 0 = unknown (conservative)")
	debug := flag.Bool("debug", false, "Print debug statements")
	enum := flag.Bool("E", false, "Enumerate valid users (safe, pre-auth-less: never increments badPwdCount)")
	aggressive := flag.Bool("Eagg", false, "Aggressive enumeration (submits pre-auth; CAN lock accounts). Implies -E")
	kerb := flag.Bool("K", false, "Test against Kerberos only")
	ldap := flag.Bool("L", false, "Test against LDAP only")
	lockerr := flag.Float64("LockErr", 1, "Distinct observed lockouts that trigger the stop-and-prompt detector")
	verbose := flag.Bool("v", false, "Print a live running tally during the run")
	flag.Parse()

	debugging = *debug

	o := &Options{
		Host:       *host,
		Hostfile:   *hostfile,
		Domain:     *domain,
		User:       *user,
		Userfile:   *userfile,
		Passfile:   *passfile,
		Pass:       *pass,
		OutFile:    *outFile,
		Lockout:    *lockout,
		Attempts:   *attempts,
		LockErr:    *lockerr,
		Sleep:      *sleep,
		Threshold:  *threshold,
		Enum:       *enum,
		Aggressive: *aggressive,
		Kerb:       *kerb,
		LDAP:       *ldap,
		Debug:      *debug,
		Verbose:    *verbose,
	}
	// -Eagg implies -E.
	if o.Aggressive {
		o.Enum = true
	}
	return o
}

// Debugf prints a debug line to stdout when -debug is set.
func Debugf(format string, v ...interface{}) {
	if debugging {
		fmt.Fprintf(os.Stdout, "[DEBUG] "+format, v...)
	}
}

// SetDebug toggles debug output (used by tests).
func SetDebug(b bool) { debugging = b }
