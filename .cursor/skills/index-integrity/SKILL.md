---
name: index-integrity
description: Scan, validate, and enforce index.mdc compliance across .cursor/.
---

# Index Integrity

Scans every directory under `.cursor/`, validates its `index.mdc` against the index rules (`.cursor/meta.mdc`), and enforces compliance by creating missing indexes and fixing stale ones.

## When to invoke

- After adding, removing, or renaming files or directories under `.cursor/`.
- After bulk operations.
- As a periodic hygiene pass.

## Behavior

1. **Scan** — recursively list every directory under `.cursor/`.
2. **Validate** — check index exists, is shallow, complete, and accurate.
3. **Report** — print summary before changes.
4. **Enforce** — create missing indexes, add missing entries, remove stale entries.

## Constraints

- **Never delete files or directories.** Only modify `index.mdc` files.
- **Idempotent.** Second run = no changes.
- **Scope: `.cursor/` only.**
