package spray

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ZerkerEOD/Talon/internal/auth"
)

// Summary renders the end-of-run report (plain text, suitable for stdout and
// the -O file).
func (s *State) Summary() string {
	var validCreds, validUsers, locked, mustChange, disabled, errors int
	totalAttempts, totalEstBadPwd := 0, 0
	for _, us := range s.users {
		totalAttempts += us.Attempts
		totalEstBadPwd += us.EstBadPwd
		if us.Succeeded {
			validCreds++
		}
		if us.Last.UserValid() {
			validUsers++
		}
		switch us.Last {
		case auth.OutcomeLocked:
			locked++
		case auth.OutcomePasswordMustChange:
			mustChange++
		case auth.OutcomeAccountDisabled:
			disabled++
		case auth.OutcomeError:
			errors++
		}
	}
	// Locked count should reflect everything observed locked, not just final state.
	locked = s.observedLocked

	var b strings.Builder
	fmt.Fprintf(&b, "\n=============== Talon run summary ===============\n")
	fmt.Fprintf(&b, "Elapsed:                 %s\n", time.Since(s.startedAt).Round(time.Second))
	fmt.Fprintf(&b, "Users processed:         %d\n", len(s.users))
	fmt.Fprintf(&b, "Valid users identified:  %d\n", validUsers)
	fmt.Fprintf(&b, "Valid credentials found: %d\n", validCreds)
	if mustChange > 0 {
		fmt.Fprintf(&b, "  (of which password-must-change: %d)\n", mustChange)
	}
	if disabled > 0 {
		fmt.Fprintf(&b, "  (of which disabled/expired:     %d)\n", disabled)
	}
	fmt.Fprintf(&b, "Accounts observed LOCKED: %d\n", locked)
	if errors > 0 {
		fmt.Fprintf(&b, "Attempts ending in error: %d\n", errors)
	}

	if s.credentialedAny {
		fmt.Fprintf(&b, "Credentialed attempts:   %d\n", totalAttempts)
		fmt.Fprintf(&b, "Estimated badPwdCount consumed (approx.): %d\n", totalEstBadPwd)
		if !s.thresholdSet {
			fmt.Fprintf(&b, "Note: -Threshold was not set, so the per-user lockout budget was not enforced.\n")
		}
	}

	// Per-DC attempt distribution (internal detail, printed when useful).
	if len(s.attemptsPerDC) > 0 {
		fmt.Fprintf(&b, "Attempts per DC:\n")
		dcs := make([]string, 0, len(s.attemptsPerDC))
		for dc := range s.attemptsPerDC {
			dcs = append(dcs, dc)
		}
		sort.Strings(dcs)
		for _, dc := range dcs {
			fmt.Fprintf(&b, "  %-24s %d\n", dc, s.attemptsPerDC[dc])
		}
	}

	// List valid credentials and locked accounts explicitly.
	if validCreds > 0 {
		fmt.Fprintf(&b, "Valid credentials:\n")
		for _, key := range s.order {
			us := s.users[key]
			if us.Succeeded {
				fmt.Fprintf(&b, "  [+] %s (%s)\n", us.Name, outcomeShort(us.Last))
			}
		}
	}
	if locked > 0 {
		fmt.Fprintf(&b, "Locked accounts:\n")
		for _, key := range s.order {
			us := s.users[key]
			if us.Locked {
				fmt.Fprintf(&b, "  [-] %s (last DC: %s)\n", us.Name, us.LastDC)
			}
		}
	}
	fmt.Fprintf(&b, "================================================\n")
	return b.String()
}

func outcomeShort(o auth.Outcome) string {
	switch o {
	case auth.OutcomeSuccess:
		return "valid"
	case auth.OutcomePasswordMustChange:
		return "valid, must change password"
	case auth.OutcomeAccountDisabled:
		return "valid, account disabled/expired"
	default:
		return "valid"
	}
}

// LiveTally returns a one-line running status for -v mode.
func (s *State) LiveTally() string {
	done := 0
	for _, us := range s.users {
		if us.Done {
			done++
		}
	}
	return fmt.Sprintf("[*] progress: %d/%d users done, %d locked observed",
		done, len(s.users), s.observedLocked)
}
