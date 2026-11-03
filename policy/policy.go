// Package policy provides named simulator targets for the differential
// oracle.
package policy

import (
	"github.com/jessburnett/deputy"
	"github.com/jessburnett/deputy/internal/sim"
)

// Vulnerable returns a target that reproduces the five bug families:
// MFA shortcut, CA gap, API-key bypass, smuggling, injection.
func Vulnerable() deputy.Target {
	return sim.New("vuln", sim.Policy{
		OBOAlways:      false,
		ValidateJWTAll: false,
		CATargets: map[string]bool{
			"docs-api":    true,
			"records-api": true,
		},
		BackendChecksACRS: false,
	})
}

// Fixed returns a target with the standard structural fixes: OBO always,
// validate-jwt everywhere, every backend in CA targets, backend verifies
// ACRS.
func Fixed() deputy.Target {
	return sim.New("fixed", sim.Policy{
		OBOAlways:      true,
		ValidateJWTAll: true,
		CATargets: map[string]bool{
			"docs-api":    true,
			"hr-api":      true,
			"legacy-api":  true,
			"records-api": true,
		},
		BackendChecksACRS: true,
	})
}
