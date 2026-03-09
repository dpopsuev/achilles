# Project Standards

## Product definition

- **Achilles**: AI-driven trust-boundary vulnerability discovery (`github.com/dpopsuev/achilles`). Built on Origami.
- **Approach:** (1) Build datasets from known CVEs (Linux kernel, RHEL, OCP). (2) Learn trust-boundary patterns. (3) Detect patterns in target codebases.
- **Targets:** RHEL, OCP.

## Current state

- PoC scaffolding: `govulncheck` wrapper (scan → classify → assess → report). Real circuit TBD.

## Methodology

- Gherkin acceptance criteria (Given/When/Then).
- Red-Orange-Green-Yellow-Blue cycle.
- `go build ./...` after every change.
- Zero imports from Asterisk or other consumers — Origami only.

## Architecture

| File | Role |
|------|------|
| `main.go` | CLI (Cobra), node/edge/extractor registration, graph walk |
| `types.go` | Severity, ScanResult, Assessment, Finding |
| `extractors.go` | GovulncheckExtractor, ClassifyExtractor |
| `nodes.go` | scan, classify, assess, report nodes |
| `circuits/achilles.yaml` | Circuit DSL |

## Scope

- Second Origami reference implementation.
- Advanced Origami features (Adversarial Dialectic, Masks, Team Walk, Ouroboros) available but unused.
