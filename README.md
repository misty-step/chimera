# chimera

Intent-driven runtime for autonomous coding agents. Every change starts from an **Intent**, runs in an isolated
**Lane**, and leaves an immutable **Capsule** of evidence that Git commits point to by trailer. The same engine
runs production work (`K=1`) and replay evaluations (`K=n`).

> **Status:** Milestone 1 in progress. The Go implementation is compiled from the Active Folio below.
> `[M1-1]` is implemented: the CLI skeleton (`--json`, exit codes `0/1/2/3`, no ANSI off a TTY),
> `chimera lint tenant-leak`, `chimera ring0 lock|verify`, and `chimera version`. `[M1-2]`–`[M1-4]` are not yet.
>
> ```sh
> go build -o chimera ./cmd/chimera && ./chimera --help
> ```

## Active Folio

| File                                   | Role                                                         |
|----------------------------------------|--------------------------------------------------------------|
| [`PRODUCT.md`](PRODUCT.md)             | What Chimera is: doctrine, primitives, config, milestones.   |
| [`DESIGN.md`](DESIGN.md)               | How it behaves: CLI contracts, Trail and Bench report design.|
| [`folio/assets/`](folio/assets/)       | Canonical assets, e.g. the reference Trail page.             |
| [`AGENTS.md`](AGENTS.md)               | Rules for agents (and people) changing this repository.      |

## Primitives

| Primitive        | One line                                                                               |
|------------------|----------------------------------------------------------------------------------------|
| **Capsule**      | Write-once, content-addressed evidence bundle in S3-compatible storage, bound by commit trailer. |
| **Lane / Bench** | `(Intent, LaneConfig) → Capsule` in an ephemeral sandbox; Bench fans out `K` lanes over a matrix. |
| **Ledger**       | Disposable SQLite + FTS5 index with authority tiers and Git-anchored freshness.        |
| **Trail**        | Review view built from trailers: risk, unmet intent, missing proof, media, transcripts.|
| **Land**         | MergeTrain: many parallel writers, one serialized, epoch-fenced lander.               |
| **Inlet**        | Authenticated owner feedback becomes Intent; everyone else goes to a triage inbox.     |

## Planned CLI (Milestone 1)

```sh
chimera lint tenant-leak                     # fail closed on tenant identifiers and secrets
chimera capsule push ./out                   # secret gate, If-None-Match: *, SHA-256 readback
chimera why pkg/capsule/push.go:42           # git blame → trailer → Capsule
chimera preflight --repo acme/widget --paths pkg/capsule
chimera bench --matrix bench.yaml -K 5       # pass rate, wall time, cost per cell
```

## Configuration

All operator-specific values (owner emails, buckets, repositories, Ring-0 paths) live in `chimera.yaml` or
`CHIMERA_*` environment variables, never in this repository. See `PRODUCT.md` §3.

## License

[MIT](LICENSE).
