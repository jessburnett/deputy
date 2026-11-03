package sim

import (
	"strings"

	"github.com/jessburnett/deputy"
)

// Policy is the simulator's knob set. Kept internal; callers use the
// named constructors in package policy.
type Policy struct {
	OBOAlways         bool
	ValidateJWTAll    bool
	CATargets         map[string]bool
	BackendChecksACRS bool
}

type Sim struct {
	name   string
	policy Policy
}

func New(name string, p Policy) *Sim {
	return &Sim{name: name, policy: p}
}

func (s *Sim) Name() string { return s.name }

func (s *Sim) Run(a deputy.Attack) (deputy.Verdict, error) {
	trace := []string{StageToken, StageGuardrail, StageGatewayAuth, StageToolNorm}

	needsStepUp := isStepUpResource(a.Args)
	entitled := !needsStepUp || a.MFA
	backend := audienceForPath(a.Args)
	caCovered := s.policy.CATargets[backend]

	if needsStepUp && !entitled {
		trace = append(trace, StageStepUp, StageCAEval)
		if !caCovered || !s.policy.BackendChecksACRS {
			trace = append(trace, StageCanary)
			return deputy.Verdict{Trace: trace, Output: a.Canary, Leaked: true}, nil
		}
		trace = append(trace, StageReject)
		return deputy.Verdict{Trace: trace}, nil
	}

	trace = append(trace, StageToolExec, StageCanary)
	return deputy.Verdict{Trace: trace, Output: a.Canary, Leaked: false}, nil
}

func isStepUpResource(path string) bool {
	return strings.Contains(path, "sensitive") || strings.Contains(path, "secret")
}

func audienceForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/hr/"):
		return "hr-api"
	case strings.HasPrefix(path, "/legacy/"):
		return "legacy-api"
	case strings.HasPrefix(path, "/records/"):
		return "records-api"
	default:
		return "docs-api"
	}
}
