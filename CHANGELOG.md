# Changelog

All notable changes. Follows [SemVer](https://semver.org).
Pre-1.0, breaking changes are documented here and bumped as minor.

## [v0.1.0] — unreleased

### Added
- `deputy.Attack`, `deputy.Verdict`, `deputy.Target` interface.
- `policy.Vulnerable()`, `policy.Fixed()` returning `Target`.
- `runner.Differential(attack, vuln, fixed)` — four-outcome oracle.
- Differential test: four verdict cases plus three real attacks
  (MFA shortcut, CA gap, entitled-clean).

### Proven
- Differential testing with a canary oracle distinguishes vulnerable
  from fixed behavior end-to-end.
