// Package spray owns the run loop and the per-user, DC-aware lockout state that
// replaces Talon's original global failure counters.
package spray

import (
	"strings"
	"time"

	"github.com/ZerkerEOD/Talon/internal/auth"
)

// rateWindow is the sliding window over which observed lockouts are counted for
// the lockout-rate detector.
const rateWindow = 60 * time.Second

// userState tracks one user across the whole run.
type userState struct {
	Name           string
	Attempts       int // cumulative credentialed attempts (metrics)
	WindowAttempts int // credentialed attempts in the current lockout window (budget)
	Failures       int // cumulative bad-password outcomes
	EstBadPwd      int // estimated badPwdCount we caused (sum across DCs)
	Locked         bool
	Succeeded      bool
	Done           bool // stop attempting: locked, valid creds found, or budget reached
	LastDC         string
	PerDCFail      map[string]int
	Last           auth.Outcome
}

// State is the shared run state.
type State struct {
	users map[string]*userState
	order []string // stable iteration order; never reordered

	safetyBudget int // max credentialed attempts per user per window (0 = unset/derived)
	thresholdSet bool

	lockErr         int
	observedLocked  int // distinct users observed locked (cumulative; for summary)
	lockedSincePmt  int // locks since the last operator prompt (detector)
	lockWindow      []time.Time
	attemptsPerDC   map[string]int
	credentialedAny bool

	startedAt time.Time
}

// NewState builds run state. attempts is int(-A) (the per-window pass budget);
// threshold is -Threshold (0 = unknown).
func NewState(usernames []string, attempts, threshold, lockErr int) *State {
	s := &State{
		users:         make(map[string]*userState),
		attemptsPerDC: make(map[string]int),
		lockErr:       lockErr,
		startedAt:     time.Now(),
	}
	if s.lockErr < 1 {
		s.lockErr = 1
	}

	// The per-user window budget is the operator's -A, hard-capped at
	// threshold-1 when the AD lockout threshold is known.
	budget := attempts
	if budget < 1 {
		budget = 1
	}
	if threshold > 0 {
		s.thresholdSet = true
		if threshold-1 < budget {
			budget = threshold - 1
		}
		if budget < 1 {
			budget = 1
		}
	}
	s.safetyBudget = budget

	for _, u := range usernames {
		key := normalizeUser(u)
		if _, ok := s.users[key]; ok {
			continue // de-duplicate
		}
		s.users[key] = &userState{Name: u, PerDCFail: make(map[string]int)}
		s.order = append(s.order, key)
	}
	return s
}

// normalizeUser strips a DOMAIN\ prefix or @domain suffix and lowercases, so the
// same account is tracked under one key regardless of how it was typed.
func normalizeUser(name string) string {
	n := strings.TrimSpace(name)
	if i := strings.LastIndex(n, "\\"); i >= 0 {
		n = n[i+1:]
	}
	if i := strings.Index(n, "@"); i >= 0 {
		n = n[:i]
	}
	return strings.ToLower(n)
}

// Order returns the stable user iteration order (normalized keys).
func (s *State) Order() []string { return s.order }

// Display returns the as-typed username for a normalized key.
func (s *State) Display(key string) string {
	if us, ok := s.users[key]; ok {
		return us.Name
	}
	return key
}

// IsDone reports whether a user should no longer be attempted at all.
func (s *State) IsDone(key string) bool {
	us, ok := s.users[key]
	return ok && us.Done
}

// ShouldSkipThisWindow reports whether a user has hit its per-window credentialed
// budget and should be skipped until the next lockout window.
func (s *State) ShouldSkipThisWindow(key string) bool {
	us, ok := s.users[key]
	if !ok {
		return false
	}
	if us.Done {
		return true
	}
	return us.WindowAttempts >= s.safetyBudget
}

// Record folds one attempt result into the state.
func (s *State) Record(r auth.AttemptResult) {
	us, ok := s.users[normalizeUser(r.User)]
	if !ok {
		return
	}
	us.Last = r.Outcome
	us.LastDC = r.Host

	if r.Credentialed {
		s.credentialedAny = true
		us.Attempts++
		us.WindowAttempts++
		s.attemptsPerDC[r.Host]++
		if r.Outcome == auth.OutcomeBadPassword {
			us.Failures++
		}
		if consumesBadPwd(r.Outcome) {
			us.EstBadPwd++
			us.PerDCFail[r.Host]++
		}
	}

	switch {
	case r.Outcome == auth.OutcomeLocked:
		if !us.Locked {
			us.Locked = true
			s.observedLocked++
			s.lockedSincePmt++
			s.lockWindow = append(s.lockWindow, time.Now())
		}
		us.Done = true
	case r.Outcome.CredentialsValid():
		us.Succeeded = true
		us.Done = true // stop hammering a found credential
	}
}

// consumesBadPwd reports whether an outcome implies a wrong-password pre-auth
// attempt was logged (incrementing the target's badPwdCount).
func consumesBadPwd(o auth.Outcome) bool {
	switch o {
	case auth.OutcomeBadPassword, auth.OutcomeUserExists, auth.OutcomeUserNoPreauth,
		auth.OutcomeSmartcardReq, auth.OutcomeDESOnly:
		return true
	default:
		return false
	}
}

// DetectorTripped reports whether the lockout-rate / cumulative-lock detector has
// crossed its threshold and the operator should be prompted.
func (s *State) DetectorTripped() bool {
	if s.lockedSincePmt >= s.lockErr {
		return true
	}
	cutoff := time.Now().Add(-rateWindow)
	recent := 0
	for _, t := range s.lockWindow {
		if t.After(cutoff) {
			recent++
		}
	}
	return recent >= s.lockErr
}

// AcknowledgeContinue resets the detector after the operator chooses to continue,
// without clearing the cumulative counts used in the summary.
func (s *State) AcknowledgeContinue() {
	s.lockedSincePmt = 0
	s.lockWindow = nil
}

// ResetWindow clears per-user window budgets at a lockout-window boundary (after
// the mandatory sleep, when the target's badPwdCount has aged out).
func (s *State) ResetWindow() {
	for _, us := range s.users {
		us.WindowAttempts = 0
	}
}

// AllDone reports whether every user is finished (locked, found, or exhausted),
// so the run can stop early instead of spinning on an empty list.
func (s *State) AllDone() bool {
	for _, us := range s.users {
		if !us.Done {
			return false
		}
	}
	return true
}

// ThresholdSet reports whether a concrete -Threshold was supplied.
func (s *State) ThresholdSet() bool { return s.thresholdSet }
