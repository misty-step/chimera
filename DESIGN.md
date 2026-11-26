# Chimera — DESIGN

> Active Folio, part 2 of 2. How Chimera looks and behaves at its two human surfaces: the command line and the
> static HTML reports (Trail, Bench). `PRODUCT.md` says what; this file says how it feels.
> The reference rendering lives in `folio/assets/trail-reference/`.

---

## 1. Command line

Chimera is a Unix tool first. Scripts and agents are its main users; humans are a close second. Every rule below
exists so that output can be piped, diffed, and trusted.

### 1.1 Grammar

```text
chimera <noun> <verb> [args] [--flags]      # chimera capsule push ./out
chimera <verb> [args]                       # top-level verbs only: run, bench, why, preflight, trail, version
```

- Nouns: `capsule`, `ledger`, `lane`, `land`, `lint`, `ring0`. Verbs are imperative and short.
- Flags are long-form GNU style (`--intent`, `--json`); the only short flags are `-K`, `-h`, `-q`.
- Positional arguments are things (paths, refs, addresses); flags are modifiers. A command never takes more than
  two positionals.
- `--help` is generated from the same table that defines the command and fits in 24 lines.

### 1.2 Streams and formats

- **stdout is data. stderr is everything else.** Progress, warnings, and hints never touch stdout.
- **`--json` on every read command** (`get`, `why`, `query`, `preflight`, `status`, `bench`, `trail --check`,
  `lint`, `version`). JSON output is one object (or JSONL for streams), with a `schema` field such as
  `"chimera.why/v1"`. Fields are only added within a schema version, never renamed or removed.
- Human output is aligned plain text. Tables use two-space gutters, no box-drawing, header row in caps.
- Ordering is deterministic: by key, then by path, then by time. Same inputs, same bytes.
- Times are RFC 3339 UTC (`2026-11-26T19:04:11Z`). Durations are integer milliseconds in JSON, `1.42s` / `3m07s`
  for humans. Hashes print in full in JSON and abbreviated to 12 hex characters for humans.

### 1.3 Exit codes

| Code | Meaning                                                                                           |
|------|---------------------------------------------------------------------------------------------------|
| `0`  | OK. The request completed and the answer is final.                                                |
| `1`  | Error. Something failed or a gate refused (leak found, hash mismatch, verifier failed, stale CAS).|
| `2`  | Usage. Bad flags, missing arguments, invalid config. Nothing was attempted.                       |
| `3`  | Pending. The request is valid but the answer is not final (lane running, change queued, upload unconfirmed). Retry later. |

No other codes. Signals exit `1` after cleanup.

### 1.4 Terminal behavior

- ANSI color and cursor control only when stdout (for data) or stderr (for progress) is a TTY **and** `NO_COLOR`
  is unset **and** `TERM` is not `dumb`. Off a TTY the output contains zero escape bytes.
- Color carries no meaning on its own. Status is always also a word: `PASS`, `FAIL`, `PENDING`, `STALE`.
- Progress is a single rewritten stderr line on TTYs, nothing otherwise. `-q` suppresses everything but data
  and errors.

### 1.5 Errors

```text
chimera: capsule push: member transcript.jsonl.zst: secret gate: 2 findings (rule cloud-key, jwt); nothing uploaded
```

- One line, lowercase, `chimera: <command>: <object>: <what failed>; <consequence or next action>`.
- With `--json`, errors are `{"schema":"chimera.error/v1","code":1,"command":"…","message":"…","findings":[…]}`
  on stdout and the human line on stderr.
- **Zero secret values in stdout or stderr, ever.** Findings name the file, line, column, and rule. Credentials
  in config or env are never echoed, even in `--debug`; they print as `<set>` or `<unset>`.

---

## 2. Static reports: Trail and Bench pages

The Trail page is where an owner decides whether to trust a change. It must read like a well-set technical
monograph: dense, calm, exact. Nothing on it is decoration; nothing on it talks to the reader.

### 2.1 Principles

- **Failures first.** Order of sections: Open risk → Unmet intent → Missing proof → Verdicts → Media → Commits.
  Empty sections collapse to a single hairline row reading `None.`
- **No single score.** Every verdict is visible. Summary counts are counts, not grades.
- **No narrator copy.** No "Great news!", no "Here's what happened", no emoji. Labels are nouns; values are data.
- **One click to the transcript.** Every verdict, risk item, and commit links to the transcript lines that
  produced it.

### 2.2 Tokens

| Token          | Light       | Dark        | Use                                                      |
|----------------|-------------|-------------|----------------------------------------------------------|
| `--paper`      | `#F6F5F2`   | `#101114`   | Page background. The only surface color.                 |
| `--ink`        | `#16171A`   | `#ECEAE4`   | Body text, values. 16.4:1 / 15.7:1.                      |
| `--muted`      | `#5B5E66`   | `#9A9DA4`   | Labels, metadata, captions. 6.0:1 / 7.0:1.               |
| `--rule`       | `#D8D5CE`   | `#2A2C31`   | 1px hairlines and table rules.                           |
| `--accent`     | `#1F45C8`   | `#7C9BFF`   | Cobalt. Links, focus, and anything needing action. 7.0:1 / 7.2:1. |

- **One accent.** Cobalt marks what needs the reader: links, focus rings, `FAIL`, open risk, unmet intent. Passing
  rows stay ink-on-paper. There is no red, green, or amber; state is carried by words and the accent rule.
- Theme follows `prefers-color-scheme`. No toggle.
- Hairlines are exactly `1px solid var(--rule)`. No shadows, no gradients, no rounded corners above `2px`.

### 2.3 Type

- `IBM Plex Sans` for prose and labels; `IBM Plex Mono` for hashes, paths, code, numbers in tables, and the
  wordmark. Bundled as self-hosted WOFF2 subsets with their OFL license. Fallbacks: `ui-sans-serif`,
  `ui-monospace`. **`Inter` is never used**, in any stack, at any weight.
- Scale (rem, 16px root): `0.75` meta · `0.875` table · `1` body · `1.25` section · `2` page title. Weights 400 and
  600 only. Line height 1.5 for body, 1.3 for headings. `font-variant-numeric: tabular-nums` on every number.
- Section labels are small caps via `text-transform: uppercase; letter-spacing: 0.06em; font-size: 0.75rem`.

### 2.4 Layout

- Desktop reference `1440×900`: 12-column grid, `max-width: 1200px`, `32px` gutters. Left 3 columns hold the
  sticky index (sections with counts); right 9 hold content.
- Mobile reference `390×844`: single column, `20px` side padding, index becomes a horizontal row of section
  links at the top. No horizontal page scroll; wide tables scroll inside their own container.
- Vertical rhythm on an `8px` base. Sections are separated by a full-width hairline and `48px` of space.
- Header block: wordmark `chimera / trail`, then the range (`base..head`), Intent ID, risk class, and four counts
  (risk, unmet, missing, verdicts), set as a definition list.

### 2.5 Components

- **Risk class** `R0`–`R3`: mono text in a `1px` box; `R2` and `R3` use the accent border.
- **Verdict row**: acceptance ID (mono) · criterion · `PASS`/`FAIL` · evidence link. `FAIL` rows carry a `2px`
  accent left rule and the word in accent.
- **Commit row**: short SHA · subject · Capsule (abbreviated hash, linked) · Intent. Missing trailers render as
  `—` and the row appears under Missing proof.
- **Media**: `<video controls preload="metadata">` and `<img>` with explicit width and height; captions are the
  file name and its acceptance ID.
- **Drill-down**: `<details>` elements; transcript excerpts in mono with line numbers that are anchors.
- **Bench table**: one row per cell; columns Model, Harness, Effort, Context, Pass rate, `x/K`, Wall p50, Wall p90,
  Cost. Best value per column is set in weight 600, never colored.

### 2.6 Platform rules

- Output is a static bundle: `index.html`, `trail.css`, optional `trail.js`, `media/`. Opens from disk or any
  static host.
- **Strict CSP**: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`. Therefore no inline
  `<style>`, no inline `<script>`, no `style=""` attributes, no third-party requests, no web fonts from CDNs.
- The page is fully readable with JavaScript disabled. `trail.js`, if present, only adds keyboard shortcuts
  (`j`/`k` between failures).
- **Motion**: none by default beyond `<details>` toggling. Under `prefers-reduced-motion: reduce` all transitions
  and smooth scrolling are off.
- Accessibility: semantic headings in order, tables with `<th scope>`, visible `2px` accent focus ring, every
  link text meaningful out of context, WCAG 2.2 AA contrast (all token pairs above exceed 4.5:1).
- No tracking, analytics, or external images. Everything the page needs is in the bundle.
