# Chimera — PRODUCT

> Active Folio, part 1 of 2. This file is the specification Chimera is compiled from.
> `DESIGN.md` is part 2 (CLI and report ergonomics). Code that disagrees with the Folio is a bug in the code,
> or a Folio change that has not been written yet. Never both.

Chimera is an intent-driven runtime for autonomous coding agents. It turns an **Intent** into **Work**, and
turns every piece of Work into immutable, replayable, reviewable evidence. One engine serves production runs
and scientific evaluation; the only difference between them is `K`.

Chimera is MIT-licensed, public, and tenant-neutral. Everything that identifies an operator lives in runtime
configuration, never in this repository.

---

## 0. Doctrine

1. **Intent is the root unit.** Nothing runs without one. Every commit, Capsule, Trail, Bench result, and proof
   resolves back to exactly one Intent.
2. **Git is the source of truth for code; the object store is the source of truth for evidence.** Everything
   else (the Ledger, Trail pages, Bench tables) is derived and rebuildable. Losing a derived artifact costs
   compute, never knowledge.
3. **Fail closed.** A gate that cannot decide refuses. A secret scanner that cannot read a file blocks the upload.
   A verifier that crashes is a failed verifier.
4. **Zero tenant hardcoding.** No operator name, email, domain, bucket, account ID, repository list, or path
   appears in code, tests, fixtures, docs, or the Folio. Tests use `example.com`, `acme`, and generated values.
5. **Measure before adding machinery.** No vector search, no embeddings, no learned ranking until exact lookup
   plus FTS5 has measurably missed on a Bench. Context policy is itself a Bench variable.
6. **Deep modules, small surfaces.** Each primitive below hides a hard problem behind a few verbs. Adding a verb
   requires a Folio change.

---

## 1. Intent

An Intent is a content-addressed statement of what should be true.

| Kind     | Source bytes                                                                    | ID                         |
|----------|---------------------------------------------------------------------------------|----------------------------|
| `folio`  | `PRODUCT.md`, `DESIGN.md`, and `folio/assets/**` at a commit                    | `folio:<sha256-hex>`       |
| `task`   | An accepted task manifest (`task.yaml`: brief, target repo, base SHA, verifier) | `task:<sha256-hex>`        |

- The hash is SHA-256 over a canonical manifest: one line per source file, sorted by path,
  `<path>\x00<git-blob-sha>\n`. Task manifests hash their canonical YAML bytes directly.
- An Intent carries **acceptance IDs** (`[M1-2]`, `[AUTH-3]`, …). Verifiers report verdicts against those IDs.
  An acceptance ID with no passing verdict is **unmet intent**.
- Every commit Chimera authors carries two trailers, in this order:

  ```text
  Chimera-Intent: folio:9c1e…(64 hex)
  Chimera-Capsule: sha256:4b7a…(64 hex)
  ```

  Trailers are the *only* binding between Git and evidence. Chimera never writes evidence into Git: no notes
  refs, no shadow branches, no checked-in databases.

---

## 2. The six primitives

### 2.1 Capsule — the single immutable evidence atom

A Capsule is a write-once, content-addressed bundle in an S3-compatible object store:

```text
cas/sha256-<hex>/
  capsule.json            # the address: <hex> = sha256(canonical bytes of this file)
  transcript.jsonl.zst    # agent transcript, zstd
  diff.patch              # base_sha..result, git format
  verdicts.json           # [{id, criterion, pass, evidence}] keyed by acceptance ID
  proof/*                 # screenshots, video, logs, coverage
```

- `capsule.json` lists every other member with `{path, sha256, size}`, plus `intent`, `checkpoint`, `repo`,
  `base_sha`, `lane` (the full LaneConfig), `started_at`, `ended_at`, and `tags`. Canonical form: UTF-8, keys
  sorted, no insignificant whitespace, no trailing newline.
- **No hash cycles.** A Capsule never contains the SHA of the commit that references it. At lane start Chimera
  allocates an opaque **checkpoint ID** (`ckpt_<ULID>`); transcripts and logs refer to the checkpoint, the sealed
  Capsule records it, and the commit records the Capsule hash. Arrows point one way: commit → Capsule → checkpoint.
- **Write protocol.** (1) Secret gate scans every byte; any finding aborts before the first network request.
  (2) Members upload first, `capsule.json` last; `capsule.json` is the commit point. (3) Every PUT sends
  `If-None-Match: *`. (4) Every PUT is followed by a GET and SHA-256 comparison. A `412` is success only if the
  readback hash matches; a mismatch is a fatal integrity error.
- **Secret gate.** Built-in rules (cloud access keys, forge tokens, chat tokens, PEM private keys, JWTs,
  high-entropy values assigned to `key|secret|token|password` names) plus every value from the tenant block of
  the loaded config, plus the optional tenant denylist. Findings report `member:line:col rule-id` and never the
  matched value. There is no silent redaction; redaction is an explicit, recorded step before packing.
- **Provenance.** `chimera why <file:line>` runs `git blame --porcelain` for that line, parses the commit's
  trailers, fetches the Capsule, and prints Intent, Capsule, lane, and the verdicts covering that file.

### 2.2 Lane and Bench — one engine for production and replay evaluation

A **Lane** is `(Intent, LaneConfig) → Capsule` on an isolated, ephemeral sandbox.

```text
LaneConfig = { model, harness, skill, prompt, effort, context_policy, runner }
context_policy ∈ { none, push, push+pull }
```

- Every production run is a Bench of `K=1`. `chimera run` and `chimera bench` share one code path.
- `Runner` is the only sandbox abstraction. It provisions a workspace at `(repo, base_sha)`, executes the
  harness command, executes the verifier, collects artifacts, and tears down. Adapters: `local` (temporary git
  worktree, for development and tests) and `boat` (remote ephemeral sandbox via its CLI). Harness and verifier
  are command templates from config; Chimera does not embed any agent.
- The **verifier** is a command run inside the sandbox after the harness. It writes `verdicts.json`; if it does
  not, its exit code becomes a single criterion. A verifier that exceeds its timeout fails.
- `chimera bench --matrix <file>` freezes fixtures `(repo, base_sha, task_brief, verifier)` and fans out `K`
  identical-start lanes over the cross product of any LaneConfig axes. Every lane is a tagged Capsule
  (`bench:<id>`, `cell:<hash>`, `k:<n>`).
- **Experiment Corpus.** The set of all Capsules is the corpus. It is append-only and populated by ordinary work
  and controlled experiments alike; there is no separate eval store.
- **Cost** is computed from harness-reported token usage and the price table in config. If usage is not
  reported, cost is `null` — never estimated.

### 2.3 Ledger — a disposable index over the object store

The Ledger is a SQLite database (Cloudflare D1 in hosted mode) with FTS5. It is derived, rebuildable, and
never committed to Git.

- **Sources.** T0 documents are read from the Git tree; everything else is replayed from Capsule manifests.
  `chimera ledger rebuild` drops the database and reconstructs it from those two sources alone.
- **Authority tiers.** Ranking is tier first, freshness second, BM25 third. A lower tier never outranks a
  higher one.

  | Tier | Contents                                                             |
  |------|----------------------------------------------------------------------|
  | `T0` | Live code, the Folio, owner rulings (`folio/rulings/*.md`) at `HEAD` |
  | `T1` | Verified evidence: Capsules with verdicts, Bench results             |
  | `T2` | Distilled claims; each must cite a `T0` or `T1` source               |
  | `T3` | External or unverified material                                      |

- **Anchors, not calendars.** Every entry is anchored to `path@blob` or `<commit>`. Freshness is mechanical: an
  entry is `fresh` when the blob at `path` on `HEAD` still equals its anchor; otherwise `drift = N` where `N` is
  the number of commits that touched `path` since the anchor. Wall-clock age never affects ranking.
- **Supersession.** An entry may declare `supersedes: <entry-id>`. Superseded entries are excluded from
  pre-flight and ranked last in queries unless `--include-superseded` is passed.
- **Pre-flight.** `chimera preflight --repo R --paths P… [--failure <text>]` emits at most 2048 bytes of scent:
  the highest-authority, freshest entries for the target paths and the normalized failure signature (digits,
  hex runs, temp paths, and timestamps stripped, then hashed). Same inputs and same Ledger produce
  byte-identical output.

### 2.4 Trail — the review view that replaces passive diffs

`chimera trail <base>..<head>` walks commit trailers and renders the evidence, not just the diff.

- Resolves every commit's Intent and Capsule; commits without trailers are listed as **missing proof**.
- Computes a **risk class** `R0`–`R3` from blast radius: config risk globs (Ring-0 paths are always `R3`), files
  and packages touched, lines changed.
- Runs **spec drift**: acceptance IDs in the Intent with no passing verdict (unmet intent), and verdicts that
  cite acceptance IDs the Intent no longer contains (orphan proof).
- Emits a concise forge check summary and a static HTML Trail page (see `DESIGN.md`): open risk, unmet intent,
  missing proof, watchable media, one-click drill-down to transcript lines. Failures are never folded into a
  single score.
- Squash and rebase preserve trailers: the lander writes the union of all source commits' trailers, de-duplicated
  and in original order.

### 2.5 Land — MergeTrain: many writers, one lander

`N` agents author on independent branches concurrently. Exactly one serialized critical section lands them.

```text
loop:
  c        ← next queued change (FIFO)
  base     ← Forge.Head(target)
  rebased  ← rebase c onto base          # conflict → evict c, continue
  verdict  ← verify(rebased) in a Lane   # verify the tree that will land, not the tree that was authored
  Forge.Push(target, old=base, new=rebased)   # compare-and-swap; stale → retry from rebase
```

- **Epoch fence.** A lander acquires epoch `n` by writing `land/<repo>/epoch-<n>` with `If-None-Match: *`. Only
  the holder of the highest epoch may push; the Forge compare-and-swap is the final fence.
- **Eviction is immediate.** A conflicted or failing change returns to its owning branch with the reason; the
  queue never stalls on it.
- **Forge** is the entire forge surface, five methods; GitHub is the first adapter, bare Git and Forgejo follow:

  ```go
  type Forge interface {
      Head(ctx context.Context, ref string) (SHA, error)
      Push(ctx context.Context, ref string, old, new SHA) error // ErrStale when ref != old
      Queue(ctx context.Context, target string) ([]Change, error)
      Report(ctx context.Context, sha SHA, check Check) error
      Notify(ctx context.Context, c Change, msg string) error
  }
  ```

### 2.6 Inlet — authenticated feedback becomes Intent

One endpoint, `POST /v1/inlet/nit`, and one web component, `<chimera-nit>`.

- **Owners** are identified by an edge-verified JWT/OIDC token whose verified email is in the tenant's
  `owner_emails`. An owner nit is classified:
  - *violates the existing Folio* → a `task` Intent referencing the violated clause (a reconcile order); the
    Folio stays unchanged and crisp.
  - *new or changed intent* → coalesced into the **one** open Folio-only PR per repo. Guards: debounce window,
    daily cap, path fence (only `PRODUCT.md`, `DESIGN.md`, `folio/**`), and an origin loop guard (nits raised
    from Chimera's own previews or bot actors are dropped).
- **Everyone else** writes only to a rate-limited triage inbox. Unauthenticated input triggers zero model calls
  and zero compute beyond the append.
- `<chimera-nit>` is a dependency-free custom element (≤ 8 KB gzipped) that captures URL, selector, viewport, and
  text. It holds no credentials; the edge session does.

### Ring-0 policy lock

Ring-0 is the set of files that judge agents: verifiers, gates, CI policy, `chimera.yaml` schema, and this
policy itself. The paths are config globs; their SHA-256 hashes live in `.chimera/ring0.lock`.

- `chimera ring0 verify` exits `1` if any Ring-0 file differs from the lock.
- A change touching Ring-0 or the lock lands only with explicit owner approval (an owner review on the forge or
  an owner-signed commit). Lanes run with Ring-0 paths read-only.

---

## 3. Configuration and tenancy

All tenant state is declarative runtime config. Precedence: flags > `CHIMERA_*` env > `chimera.yaml`
(`./chimera.yaml`, then `$XDG_CONFIG_HOME/chimera/chimera.yaml`). Public repositories commit only
`chimera.example.yaml`.

```yaml
# chimera.example.yaml — placeholder values only
tenant:
  owner_emails: [owner@example.com]
  repos: [acme/widget]
  denylist_file: ~/.config/chimera/denylist.txt   # extra private terms, one per line, never committed
store:
  endpoint: https://s3.example.com
  bucket: acme-capsules
  region: auto
ledger:
  path: ~/.local/state/chimera/ledger.db
ring0:
  paths: [".github/workflows/**", "verify/**", ".chimera/**"]
runners:
  local: {}
  boat: { command: boat }
harnesses:
  example-agent: { command: ["example-agent", "--prompt-file", "{{.PromptFile}}"] }
prices:
  example-model: { input_per_mtok: 1.00, output_per_mtok: 4.00 }
```

- Secrets come only from env (`CHIMERA_S3_ACCESS_KEY_ID`, `CHIMERA_S3_SECRET_ACCESS_KEY`, …). A config file
  containing a secret-shaped value is a load error.
- Every tenant value in the loaded config is automatically part of the tenant-leak denylist.

---

## 4. Implementation constraints

- Go 1.23+, one module, one binary: `cmd/chimera`. `go vet ./...` and `go test ./...` are clean.
- Layout: `cmd/chimera` (entry only) · `internal/cli` (commands, output, exit codes) · `pkg/config` ·
  `pkg/secretscan` · `pkg/objstore` (S3 SigV4 client + loopback fake) · `pkg/gitx` (trailers, blame) ·
  `pkg/capsule` · `pkg/ledger` · `pkg/lane` · later `pkg/trail`, `pkg/land`, `pkg/forge`, `pkg/inlet`,
  `web/chimera-nit`.
- Dependencies, exhaustively: the standard library, `modernc.org/sqlite` (pure Go, FTS5, no cgo),
  `github.com/klauspost/compress/zstd`, `gopkg.in/yaml.v3`. No cloud SDKs; SigV4 is implemented and tested
  against the published AWS signing test vectors. Adding a dependency is a Folio change.
- Git is invoked as the `git` binary; no Git libraries.
- Tests never touch the network. Object store tests use the in-process fake; Runner tests use `local`.
- Each test that proves an acceptance criterion names it: `TestM1_2_PutIsWriteOnce`.

---

## 5. Milestone 1 — evidence core (target: first reconciler pass)

M1 ships a working, tested CLI. Each item is done when its listed tests pass and the commands work against a
real Git repository and the loopback object store fake.

**[M1-1] Module, CLI skeleton, tenant-leak lint, Ring-0 verify.**
- `go.mod` (Go 1.23), `cmd/chimera`, `internal/cli` implementing the conventions in `DESIGN.md` (`--json`,
  exit codes `0/1/2/3`, no ANSI off-TTY). `chimera version --json` prints module version and VCS revision.
- `chimera lint tenant-leak [paths…]` scans tracked files (`git ls-files`) or the given paths against the secret
  gate rules, the loaded tenant values, and the denylist file. Matching is case-insensitive at word boundaries.
  Exits `1` on any finding, printing `path:line:col rule-id` without the matched value. Exits `1` if the
  denylist file is configured but unreadable.
- `chimera ring0 lock|verify` per the Ring-0 section.
- Tests: a fixture repo seeded with a generated tenant term fails; the same repo clean passes; output never
  contains the term; binary files are scanned; unreadable denylist fails closed.

**[M1-2] `pkg/capsule` and `chimera capsule pack|push|get|attach|why`.**
- `pack <dir> --intent <id> --checkpoint <id>` builds canonical `capsule.json` and prints the address.
- `push <dir>` runs the secret gate, uploads with `If-None-Match: *`, reads back and verifies every member.
- `get <sha256:hex> [--out dir]` downloads and verifies every member hash.
- `attach <commit> <sha256:hex> --intent <id>` adds both trailers (via `git interpret-trailers`) to `HEAD` or
  rewrites the named unpushed commit; refuses if the Capsule is not in the store.
- `why <file:line>` resolves blame → trailers → Capsule.
- Tests against the loopback fake (which verifies SigV4 signatures): two concurrent pushes of one Capsule
  produce exactly one write and two successes; a fake that corrupts a stored member makes `push` and `get`
  fail; a secret in `transcript.jsonl.zst` aborts with zero requests reaching the fake; `pack` is deterministic
  across runs and machines; `why` resolves a line committed with trailers and exits `1` on a line without them.

**[M1-3] `pkg/ledger` and `chimera ledger index|query|preflight|rebuild`.**
- Schema: `entries(id, tier, kind, repo, path, anchor, intent, capsule, supersedes, body)`, FTS5 table over
  `body` and `path`, plus `lanes(capsule, bench, cell, k, model, harness, effort, context_policy, pass_rate,
  wall_ms, cost_usd)`.
- `index` adds the current Git tree's T0 documents and any new Capsules. `query <text> [--tier] [--path]`
  ranks tier → freshness → BM25. `preflight` per §2.3. `rebuild` drops and replays.
- Tests: tier ordering holds even when a lower tier has a better BM25 score; editing an anchored file marks the
  entry `drift=1`; superseded entries are excluded from pre-flight; pre-flight never exceeds 2048 bytes and is
  byte-stable; **drop-and-rebuild equivalence**: incremental `index` and `rebuild` produce identical
  `ledger dump --canonical` SHA-256.

**[M1-4] `pkg/lane` and `chimera run` / `chimera bench`.**
- `Runner` interface with `local` and `boat` adapters; `local` is fully tested, `boat` is tested with a fake
  `boat` executable on `PATH`.
- `run --intent <id> --lane <name>` executes one lane and produces a Capsule (and, with `--apply`, a commit
  carrying both trailers in the current repo).
- `bench --matrix <file> [-K n]` fans out lanes over frozen fixtures and prints a table per cell: Criterion
  Pass Rate, all-criteria pass count `x/K`, Wall Time p50/p90, Cost (or `—` when unknown). `--json` emits the
  same rows. Every lane's Capsule is tagged and indexed.
- Tests: a fixture task whose verifier passes only for one harness yields pass rates `1.00` and `0.00` for the
  two cells; all `K` lanes start from the same `base_sha` and tree; a harness that times out produces a Capsule
  with a failing verdict, not a missing one; `run` equals `bench -K 1` on the same inputs.

---

## 6. Milestone 2 — review, landing, feedback

**[M2-1] Trail.** `pkg/trail` and `chimera trail <base>..<head> [--html dir] [--check]`: trailer walk, risk class,
spec drift, missing proof, forge check summary, and the static HTML Trail and Bench pages specified in
`DESIGN.md`. Tests: golden HTML for a fixture history; a commit without trailers appears under missing proof;
squash preserves the trailer union.

**[M2-2] Land.** `pkg/forge` (the five-method interface; GitHub adapter; in-memory fake) and `pkg/land`
(`chimera land enqueue|status|run`). Tests against the fake forge: `N` concurrent branches land serially with
every landed tree verified post-rebase; a conflicting change is evicted while the next lands; a stale CAS
retries; two landers never both push within one epoch.

**[M2-3] Inlet.** `pkg/inlet` (`POST /v1/inlet/nit`, edge JWT verification against configured issuer and
`owner_emails`, reconcile-vs-Folio routing, coalesced Folio-only PR with debounce, daily cap, path fence, loop
guard; triage inbox for everyone else) and `web/chimera-nit`. Tests: an unsigned or non-owner token never
reaches the classifier; the daily cap holds; a nit from a Chimera preview origin is dropped; a Folio-only PR
never touches paths outside the fence.

---

## 7. Non-goals

- A hosted SaaS, accounts, or billing. Chimera is a binary plus your own object store.
- An agent or model wrapper. Harnesses are external commands.
- Embedding or vector retrieval (until a Bench shows FTS5 missing; see Doctrine 5).
- Evidence storage in Git, and Git storage in the object store.
