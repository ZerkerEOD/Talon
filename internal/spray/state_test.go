package spray

import (
	"testing"

	"github.com/ZerkerEOD/Talon/v4/internal/auth"
)

func TestNormalizeUser(t *testing.T) {
	cases := map[string]string{
		`CORP\Alice`:     "alice",
		"bob@corp.local": "bob",
		"  Carol ":       "carol",
		"dave":           "dave",
	}
	for in, want := range cases {
		if got := normalizeUser(in); got != want {
			t.Fatalf("normalizeUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func cred(user string, o auth.Outcome) auth.AttemptResult {
	return auth.AttemptResult{Outcome: o, User: user, Host: "dc1", Credentialed: true}
}

// TestSafetyBudgetStopsBeforeLockout: with threshold 3, a user may be attempted
// at most twice (threshold-1) in a window, so Talon never submits the attempt
// that would cross the lockout threshold.
func TestSafetyBudgetStopsBeforeLockout(t *testing.T) {
	st := NewState([]string{"alice"}, 10 /*-A*/, 3 /*threshold*/, 5 /*lockErr*/)
	key := normalizeUser("alice")

	if st.ShouldSkipThisWindow(key) {
		t.Fatal("alice should be attemptable before any attempt")
	}
	st.Record(cred("alice", auth.OutcomeBadPassword))
	if st.ShouldSkipThisWindow(key) {
		t.Fatal("alice should still be attemptable after 1 of 2 budget attempts")
	}
	st.Record(cred("alice", auth.OutcomeBadPassword))
	if !st.ShouldSkipThisWindow(key) {
		t.Fatal("alice should be skipped after reaching threshold-1 attempts")
	}

	// A fresh window resets the per-user budget.
	st.ResetWindow()
	if st.ShouldSkipThisWindow(key) {
		t.Fatal("alice should be attemptable again after ResetWindow")
	}
}

// TestDetectorTripsOnInterleavedLocks: the detector must trip on cumulative
// distinct locks even when non-lock results are interleaved — the exact case
// the original consecutive-counter missed.
func TestDetectorTripsOnInterleavedLocks(t *testing.T) {
	st := NewState([]string{"alice", "bob", "carol", "dave"}, 1, 0, 2 /*lockErr=2*/)

	st.Record(cred("alice", auth.OutcomeBadPassword))
	st.Record(cred("bob", auth.OutcomeLocked))
	if st.DetectorTripped() {
		t.Fatal("detector tripped after only 1 lock (lockErr=2)")
	}
	st.Record(cred("carol", auth.OutcomeBadPassword)) // interleaved non-lock
	if st.DetectorTripped() {
		t.Fatal("a non-lock result must not trip or reset the detector incorrectly")
	}
	st.Record(cred("dave", auth.OutcomeLocked))
	if !st.DetectorTripped() {
		t.Fatal("detector should trip after 2 distinct locks")
	}

	// AcknowledgeContinue resets the detector but preserves cumulative count.
	st.AcknowledgeContinue()
	if st.DetectorTripped() {
		t.Fatal("detector should be reset after AcknowledgeContinue")
	}
	if st.ObservedLocked() != 2 {
		t.Fatalf("ObservedLocked = %d, want 2 (cumulative preserved)", st.ObservedLocked())
	}
}

// TestDoneSkipWithoutReorder: a locked/succeeded user becomes Done and is skipped,
// and the iteration order is never mutated (the original swap-remove bug).
func TestDoneSkipWithoutReorder(t *testing.T) {
	users := []string{"alice", "bob", "carol"}
	st := NewState(users, 1, 0, 100)
	orderBefore := append([]string(nil), st.Order()...)

	st.Record(cred("bob", auth.OutcomeLocked))
	if !st.IsDone(normalizeUser("bob")) {
		t.Fatal("bob should be Done after a lock")
	}

	st.Record(auth.AttemptResult{Outcome: auth.OutcomeSuccess, User: "carol", Host: "dc1", Credentialed: true})
	if !st.IsDone(normalizeUser("carol")) {
		t.Fatal("carol should be Done after valid credentials")
	}

	orderAfter := st.Order()
	if len(orderAfter) != len(orderBefore) {
		t.Fatalf("order length changed: %d -> %d", len(orderBefore), len(orderAfter))
	}
	for i := range orderBefore {
		if orderBefore[i] != orderAfter[i] {
			t.Fatalf("order mutated at %d: %q -> %q", i, orderBefore[i], orderAfter[i])
		}
	}

	if st.AllDone() {
		t.Fatal("not all users done yet (alice remains)")
	}
	st.Record(cred("alice", auth.OutcomeLocked))
	if !st.AllDone() {
		t.Fatal("AllDone should be true once every user is resolved")
	}
}

// TestSafeEnumNotCountedAgainstBudget: non-credentialed (safe-enum) results must
// not consume the per-user attempt budget or the badPwdCount estimate.
func TestSafeEnumNotCountedAgainstBudget(t *testing.T) {
	st := NewState([]string{"alice"}, 10, 3, 5)
	key := normalizeUser("alice")
	for i := 0; i < 20; i++ {
		st.Record(auth.AttemptResult{Outcome: auth.OutcomeUserExists, User: "alice", Host: "dc1", Credentialed: false})
	}
	if st.ShouldSkipThisWindow(key) {
		t.Fatal("safe-enum probes must not exhaust the credentialed budget")
	}
}
