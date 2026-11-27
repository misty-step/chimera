# AGENTS.md

Rules for any agent or person changing this repository. Short on purpose; the Folio is the long part.

## Source of truth

1. `PRODUCT.md` and `DESIGN.md` are the specification. Read both before writing code.
2. If code and Folio disagree, fix the code — or change the Folio in the same PR and say so. Never leave them
   disagreeing.
3. Work against acceptance IDs (`[M1-1]`…`[M2-4]`). Build Milestone 1 in order; do not start M2 until M1 is green.

## Hard rules

- **Public repo, zero tenant data.** No operator names, emails, domains, bucket names, account IDs, repository
  lists, or personal paths in code, tests, fixtures, docs, or commit messages. Use `example.com`, `acme`, and
  generated values. Real values belong in `chimera.yaml` or env, which are never committed.
- **No secrets anywhere.** Not in code, logs, test output, Capsules, or PR text.
- **Ring-0 is read-only to agents.** Verifiers, gates, CI policy, and `.chimera/ring0.lock` change only with owner
  approval.
- **Dependencies are fixed** by `PRODUCT.md` §4. Adding one is a Folio change.
- **No evidence in Git.** No checked-in Ledger databases, no notes refs, no shadow branches.

## Done means

```sh
gofmt -l .                 # prints nothing
go vet ./...
go test ./...
chimera lint tenant-leak   # once [M1-1] exists
```

…all clean, plus the acceptance tests for the IDs you claim, named `TestM<milestone>_<n>_<What>`.

## Commits

- Conventional, imperative subject (`capsule: verify readback hash`), one logical change each.
- Chimera-authored commits end with `Chimera-Intent:` and `Chimera-Capsule:` trailers. Never strip trailers when
  rebasing or squashing.
