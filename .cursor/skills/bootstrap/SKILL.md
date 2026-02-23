---
name: bootstrap
description: Create/verify .cursor structure (project-agnostic).
disable-model-invocation: true
---

# /bootstrap

## Purpose
Create or verify the agreed `.cursor` directory structure and shallow indexes.

## Scope
- Create missing `.cursor` subdirectories (per `.cursor/meta.mdc`).
- Create missing `index.mdc` files (shallow, direct children only).
- Do **not** scan the repo or infer domain knowledge.
- Do **not** update existing indexes — use index-integrity skill for that.
- Safe to run repeatedly; no destructive changes.
