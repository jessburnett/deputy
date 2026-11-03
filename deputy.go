// Package deputy tests whether an agent acting for a user preserves the
// user's identity across the agent-tool boundary.
package deputy

// Attack is one tool invocation in one user's session.
type Attack struct {
	User   string
	MFA    bool
	Tool   string
	Args   string
	Canary string
}

// Verdict is what the target observed.
type Verdict struct {
	Trace  []string
	Output string
	Leaked bool
}

// Target is what the harness fires attacks at. The simulator targets in
// package policy implement it; a production agent implements it once.
type Target interface {
	Name() string
	Run(Attack) (Verdict, error)
}
