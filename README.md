# deputy

Differential test harness for the identity boundary between an AI agent
and the tools it calls on a user's behalf.

## The problem

An agent acts for a user but uses its own identity. If that identity is
app-only, the user's MFA, Conditional Access, and step-up controls never
apply to the actual call. The action happens, the user believes they
authorized it, and none of their controls ran. Every component can be
individually correct while the system leaks — the bug is in the
composition, not any single piece.

The test question: *for a given request, does the identity the backend
authorizes match the identity the user believes is acting?*

## The method

Two targets run the same code and differ only in policy knobs. Fire the
same attack at both. A unique canary string in the target file tells you
whether the leak happened.

| vuln | fixed | verdict |
|---|---|---|
| leaks | clean | **Finding** — real bug, fix covers it |
| leaks | leaks | **Regression** — fix incomplete |
| clean | clean | **Clean** — this attack doesn't apply here |
| clean | leaks | **Inconclusive** — investigate the harness |

No LLM judge. The canary is ground truth.

`Clean` means "these attacks found nothing." Not "secure."

## What this repo is (v0.1.0)

The minimum that demonstrates the method: `Attack`, `Verdict`, `Target`,
a `Differential` runner with four outcomes, and two named targets
(`policy.Vulnerable()` and `policy.Fixed()`) that fire three canonical
attacks. Everything else — chains, identity scenarios, the corpus
integrity gate, ADR-025 — is what grows on top of this.

## Using it

```go
import (
    "github.com/jessburnett/deputy"
    "github.com/jessburnett/deputy/policy"
    "github.com/jessburnett/deputy/runner"
)

attack := deputy.Attack{
    User:   "alice",
    MFA:    false,
    Tool:   "read_file",
    Args:   "/docs/sensitive.txt",
    Canary: "unique-secret-string",
}
got, err := runner.Differential(attack, policy.Vulnerable(), policy.Fixed())
// got == runner.Finding  → the fix covers this attack
// got == runner.Regression → the fix is incomplete
```

To test your own agent, implement `deputy.Target`:

```go
type myAgent struct{ /* ... */ }

func (m *myAgent) Name() string { return "prod-agent" }
func (m *myAgent) Run(a deputy.Attack) (deputy.Verdict, error) {
    // Issue the attack through your agent; return the trace and
    // whether the canary surfaced in the output.
}
```

## What this is not

- **Not a model safety tool.** No prompts, no jailbreaks, no model evaluation.
- **Not a tenant scanner.** Runs against a simulator; a real-tenant adapter is not yet present.
- **Not a proof of security.** `Clean` bounds what these attacks found, not what's exploitable.
- **Not immune to common-mode failure.** `vuln` and `fixed` share code; a bug in a shared component would be invisible to the oracle.

## References

- Confused deputy pattern: Hardy, *The Confused Deputy* (1988).
- On-behalf-of flow: Microsoft Entra ID documentation.
- Conditional Access and authentication context: Microsoft Entra ID documentation.

## License

Apache 2.0. See [LICENSE](LICENSE).
