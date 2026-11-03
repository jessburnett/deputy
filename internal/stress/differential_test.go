package stress

import (
	"testing"

	"github.com/jessburnett/deputy"
	"github.com/jessburnett/deputy/policy"
	"github.com/jessburnett/deputy/runner"
)

type mockTarget struct {
	name  string
	leaks bool
}

func (m mockTarget) Name() string { return m.name }
func (m mockTarget) Run(deputy.Attack) (deputy.Verdict, error) {
	return deputy.Verdict{Leaked: m.leaks}, nil
}

// TestDifferentialOutcomes: all four verdicts are reachable.
func TestDifferentialOutcomes(t *testing.T) {
	a := deputy.Attack{User: "alice", MFA: false}
	cases := []struct {
		name        string
		vuln, fixed bool
		want        runner.Result
	}{
		{"finding", true, false, runner.Finding},
		{"regression", true, true, runner.Regression},
		{"clean", false, false, runner.Clean},
		{"inconclusive", false, true, runner.Inconclusive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := runner.Differential(a,
				mockTarget{"v", c.vuln}, mockTarget{"f", c.fixed})
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestRealAttacksFire: two canonical attacks from the five families
// discriminate vuln from fixed, and an entitled user is clean on both.
func TestRealAttacksFire(t *testing.T) {
	vuln := policy.Vulnerable()
	fixed := policy.Fixed()

	cases := []struct {
		name   string
		attack deputy.Attack
		want   runner.Result
	}{
		{
			name: "mfa-shortcut-fires",
			attack: deputy.Attack{
				User: "alice", MFA: false, Tool: "read_file",
				Args: "/docs/sensitive.txt", Canary: "SECRET-MFA",
			},
			want: runner.Finding,
		},
		{
			name: "ca-gap-fires",
			attack: deputy.Attack{
				User: "alice", MFA: false, Tool: "hr_read",
				Args: "/hr/secret.txt", Canary: "SECRET-CA",
			},
			want: runner.Finding,
		},
		{
			name: "entitled-user-clean",
			attack: deputy.Attack{
				User: "alice", MFA: true, Tool: "read_file",
				Args: "/docs/sensitive.txt", Canary: "SECRET-ENTITLED",
			},
			want: runner.Clean,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := runner.Differential(c.attack, vuln, fixed)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
