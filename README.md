# chimera

Intent-driven runtime for autonomous coding agents. Every change starts from an **Intent**, runs in an isolated
**Lane**, and leaves an immutable **Capsule** of evidence that Git commits point to by trailer. The same engine
runs production work (`K=1`) and replay evaluations (`K=n`).

> **Status:** Milestone 1 (evidence core) is implemented: `[M1-1]` CLI skeleton, tenant-leak lint, Ring-0 lock;
> `[M1-2]` Capsules and `why`; `[M1-3]` the Ledger and pre-flight; `[M1-4]` `run` and `bench`. Milestone 2
> (Trail, Land, Inlet) is not started. The Go implementation is compiled from the Active Folio below.
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

## CLI (Milestone 1)

```sh
chimera lint tenant-leak                          # fail closed on tenant identifiers and secrets
chimera ring0 lock && chimera ring0 verify        # hash the files that judge agents; exit 1 on any change

chimera capsule pack ./out --intent folio:<sha256> --checkpoint ckpt_<ULID>   # canonical capsule.json → address
chimera capsule push ./out                        # secret gate, If-None-Match: *, SHA-256 readback
chimera capsule get sha256:<hex> --out ./copy     # download and verify every member
chimera capsule attach HEAD sha256:<hex>          # Chimera-Intent + Chimera-Capsule trailers
chimera why pkg/capsule/push.go:42                # git blame → trailers → Capsule, with HEAD-N drift

chimera ledger rebuild                            # drop the SQLite FTS5 index; replay Git and the store
chimera ledger query "readback" --tier T1         # rank: tier, then freshness, then BM25
chimera preflight pkg/capsule --failure "…"       # at most 2048 bytes of scent

chimera run --intent folio --lane default         # one lane (K=1) → Capsule; --apply commits with trailers
chimera bench --matrix bench.yaml -K 5 --html out # pass rate, x/K, wall p50/p90, cost per cell
```

Every read command takes `--json` and emits one object with a `schema` field. Exit codes are `0` ok, `1` error
or refused gate, `2` usage, `3` pending. `capsule write|read|verify` and `ledger status|dump` are shorthands over
the verbs above.

`store.endpoint` is an S3-compatible URL (path-style, SigV4, credentials from `CHIMERA_S3_*`) or
`file:///absolute/dir` for a local directory with the same write-once semantics. Lanes, harnesses, and verifiers
are command templates in `chimera.yaml`; see [`chimera.example.yaml`](chimera.example.yaml).

## Configuration

All operator-specific values (owner emails, buckets, repositories, Ring-0 paths) live in `chimera.yaml` or
`CHIMERA_*` environment variables, never in this repository. See `PRODUCT.md` §3.

## License

[MIT](LICENSE).
