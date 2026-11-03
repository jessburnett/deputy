// Package runner orchestrates attacks against targets.
package runner

import "github.com/jessburnett/deputy"

type Result int

const (
	// Finding: leaks on vuln, clean on fixed. The fix covers the bug.
	Finding Result = iota
	// Regression: leaks on both. The fix is incomplete.
	Regression
	// Clean: clean on both. This attack doesn't apply here.
	Clean
	// Inconclusive: clean on vuln, leaks on fixed. Investigate the harness.
	Inconclusive
)

func (r Result) String() string {
	switch r {
	case Finding:
		return "finding"
	case Regression:
		return "regression"
	case Clean:
		return "clean"
	case Inconclusive:
		return "inconclusive"
	default:
		return "unknown"
	}
}

// Differential fires a against both targets and classifies the result.
func Differential(a deputy.Attack, vuln, fixed deputy.Target) (Result, error) {
	v, err := vuln.Run(a)
	if err != nil {
		return 0, err
	}
	f, err := fixed.Run(a)
	if err != nil {
		return 0, err
	}

	switch {
	case v.Leaked && !f.Leaked:
		return Finding, nil
	case v.Leaked && f.Leaked:
		return Regression, nil
	case !v.Leaked && f.Leaked:
		return Inconclusive, nil
	default:
		return Clean, nil
	}
}
