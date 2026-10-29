# Maintenance Log

This project is maintained by an AI agent (lobo) working under the
direction of its owner, hash. This log is the public record of that
maintenance: what broke, how it was diagnosed, what changed, and how
each change was verified. Claims in this log can be checked against
the commits and workflow runs it cites.

## 2026-10-27: Scheduled scans restored

**Symptom.** The "AML Roaster — Scheduled Scan" workflow showed a
"cancelled" conclusion on every run, and no report had landed since
2026-07-04.

**Diagnosis.** Run records showed the same shape every time: setup
steps passed in seconds, then the scan step ran until GitHub killed
the job at about 10 minutes 19 seconds, the workflow's timeout. The
scan legitimately needs longer than 10 minutes on heavy batches
(multiple watched addresses, exchange hot wallets backfilling tens
of thousands of blocks, API rate limits), so it never reached the
step that commits its report.

**Changes.**
- `roaster.py`: an in-script time budget
  (`ROASTER_TIME_BUDGET_SECONDS`, default 900), checked before each
  watched address and inside the per-sender profiling loops. When
  the budget runs out, the scan stops starting new work and writes
  its report with what it completed. A partial report says so, in a
  "Partial Run" note listing the deferred addresses, and the
  rotation resumes at the first deferred address next run.
  (Commits e317172, b1d6362. No scoring, threshold, or watched-list
  changes. All 66 existing tests pass.)
- `.github/workflows/roaster.yml`: job timeout raised first to 25
  minutes, then to 60, because report generation (one AI summary
  call per finding, with pauses) took about 10.5 minutes on a
  569-finding batch and pushed a fully completed run past 25.

**Verification.** Dispatch run 40561294861 completed every step,
including the report commit: `reports/report_2026-10-27_1900.md`
(bot commit fa1c5dd), the first scheduled-path report since
2026-07-04. It scanned 5 of 8 batch addresses (569 findings) and
deferred 3, exactly as the partial-run note records. The first
confirmation run under the 60-minute timeout (40565910452) completed
its scan but lost its report at the commit step: its push was
rejected because main had moved during the scan. The commit step
now rebases onto the latest main and retries the push (commit
ca28e38). Verification run 40574607797 with that fix succeeded end
to end (2026-10-27, 20:03 to 20:21 UTC), landing report commit
1167ec6 (`reports/report_2026-10-27_2021.md`), and the GitHub Pages
deployment of the updated dashboard succeeded.

## 2026-10-27: Address feed refresh unblocked

**Symptom.** The weekly "Refresh Address Feeds" workflow failed in
about 9 seconds, every week since at least 2026-08-23.

**Diagnosis.** The run's own annotations named the cause: "GitHub
Actions is not permitted to create or approve pull requests." The
refresh step itself succeeded every time; the final step, which
opens a pull request with the refreshed OFAC data, was refused by a
repository setting.

**Changes.**
- Repository setting enabled: allow GitHub Actions to create and
  approve pull requests. The repository's default token permissions
  were deliberately left at "read"; this workflow already declares
  the two write scopes it needs for itself.
- `.github/workflows/refresh-addresses.yml`: actions updated
  (checkout v7, setup-python v7, create-pull-request v8, which also
  clears a Node.js 20 deprecation warning), a concurrency guard so
  manual and scheduled runs cannot race, and a header comment
  documenting the setting dependency. (Commit 439f480.)

**Verification.** Dispatch run 40552756832 succeeded with every
step green, and opened pull request #8 carrying the refreshed OFAC
data (addresses/ofac.json, 33 lines added). Annotations dropped
from 3 to a single informational notice from GitHub. PR #8 was
merged on 2026-10-27 at 19:25 UTC (merge commit e7fc19f), so the
refreshed OFAC data is on main.

## 2026-10-27: Reviewer audit fixes

Two independent reviewers (Claude and Wukong) audited this repo
after the repairs above. Every finding below was verified against
the code and the run records before being fixed.

**Findings and changes.**
- The AI commentary model was dead. `roaster.py` pointed at a Groq
  model this repo's key can no longer call (the API returns 404),
  so all 127 findings in the 20:21 report carried a raw "Automated
  analysis error" string in place of commentary, and a failed call
  also relabeled the finding's verdict as "API error". The model
  is now `openai/gpt-oss-20b`. A failed commentary call no longer
  writes any error text into the report and can never change a
  verdict: the verdict comes from the rule score alone. Failures
  are counted and reported as a single summary line.
- Commentary is capped at the 25 highest-scoring findings per run
  (`MAX_ANALYSES_PER_RUN`). One call plus a pause per finding was
  most of the report-generation time on heavy batches; findings
  past the cap keep their full rule-based verdict.
- The unverified "94.9% detection rate" figure was removed from
  `roaster.py` (the docstring, a thresholds comment, and the
  report header). No threshold values changed.
- Partial reports did not reconcile coverage with findings: the
  20:21 report said 0 of 8 batch addresses were scanned yet listed
  127 findings. Findings are raised while an address is being
  profiled, so an address cut short by the time budget leaves
  preliminary findings behind while still counting as deferred.
  The Partial Run note now says so, with the count, and states
  that those findings are re-derived in full when the address is
  scanned again on the next run.
- The "Sync threat feeds" workflow could never detect a change:
  it downloads into the untracked `engine-sync/` directory but its
  check used `git diff`, which ignores untracked files, so five
  straight "success" runs synced nothing. The check now uses
  `git status --porcelain`, the downloads fail loudly on HTTP
  errors (`curl -f`), and its actions were bumped to match the
  rest of the repo (checkout v7, create-pull-request v8).
- The scan schedule claimed every 30 minutes, which a run that
  takes 18 to 30 minutes cannot sustain and GitHub does not
  deliver reliably at that cadence. The cron is now every 6
  hours, and the README status says so.

- Commentary parsing was hardened after the verification run
  below: the new model answered, but 17 of 25 replies did not
  parse as strict JSON, and the parse-failure fallback printed
  the raw reply into the report. The call now requests JSON
  mode, allows 1600 tokens, and extracts the outermost JSON
  object from the reply before parsing. A reply that still
  cannot be parsed now falls back to the same clean generic
  text as a failed call. Raw model output never appears in a
  report.

**Verification.** All 66 existing tests pass. Verification run
40582225156 (2026-10-27, success) produced
reports/report_2026-10-27_2114.md: clean header with no rate
claim, zero analysis-error strings, a Partial Run note (3 of 8
scanned) with a coverage note reconciling its 236 preliminary
findings, and an honest summary line for the 17 commentary
replies that failed to parse. The parse hardening above was
smoke-tested locally (wrapped JSON parses; unparseable output
falls back cleanly with no raw text in the report). A
confirmation run with the hardening has been dispatched; its
conclusion will be appended here when it lands.

## 2026-10-28: confirmation results and scheduled-run proof

- Confirmation run 40597029199 (2026-10-27 22:56 UTC, dispatched)
  produced a clean report: no 94.9% figure, no analysis-error
  strings, no raw JSON, and genuine AI commentary on its first
  finding. One generated verdict sentence in that report overstated
  pattern risk as laundering risk; the prompt guard in 5b0c520 now
  instructs pattern-risk language only, never proven crime.
- JSON mode was removed in 7b93941 after Groq returned HTTP 400
  "Failed to validate JSON" on 12 of 25 capped calls. Tolerant
  extraction without JSON mode is the shipped configuration.
- The generated-file rebase conflict that failed run 40599783489
  was fixed in 5b0c520: conflicts under reports/ resolve in favour
  of the newest run; conflicts outside reports/ abort the push.
- Scheduled proof: the six-hour cron (0 */6 * * *) produced its
  first automatically triggered successful runs on 2026-10-28.
  Run 40633500623 (created 04:38:56Z, event: schedule, success)
  pushed reports/report_2026-10-28_0439.md (1 finding). Run
  40686971258 (created 12:20:18Z, event: schedule, success)
  pushed reports/report_2026-10-28_1223.md (11 findings). No run
  was created at the 00:00Z slot itself; GitHub's scheduler
  delivered the cadence late, but the automatic path is now
  demonstrated end to end, twice.
- Commentary yield on those scheduled runs, shipped
  configuration: 6 of 12 findings carry generated commentary; the
  other 6 fall back to clean template text. Neither report
  contains error strings, raw model output, or the removed 94.9%
  figure. One 12:23 commentary overstates its rule basis: it
  describes Railgun Treasury as black-listed by the US Treasury,
  while the firing rule was stablecoin_mixing (+80) on a transfer
  of about $2 to a privacy protocol, and Railgun is not an
  OFAC-listed entity. The prompt guard reduces but does not
  eliminate overstatement; treat AI commentary as illustrative,
  not evidentiary.

## 2026-10-28: AI commentary disabled

AI commentary produced false sanctions and laundering statements
(for example FixedFloat and Railgun described as sanctioned, and
pattern hits described as proven laundering). Rule verdicts were
not changed. A correction notice now opens the Oct 27 partial
report, `reports/report_2026-10-27_2114.md` (Partial Run: 3 of 8
addresses scanned; `reports/report_2026-10-27_2256.md` is a
completed confirmation run and is not the partial), and the three
Oct 28 scheduled reports (`report_2026-10-28_0439.md`,
`report_2026-10-28_1223.md`, `report_2026-10-28_2228.md`).

`MAX_ANALYSES_PER_RUN` is 0. Scheduled reports contain rule verdicts
and template text only. The cap is a constant: no environment
variable and no workflow input can raise it, and `generate_roast()`
does not call the model while it is 0. Re-enable only after an
output filter exists and one scheduled report greps clean.

Each new report states, near the top, addresses attempted, addresses
fully scanned, and fetch failures (Etherscan rate-limit and other
errors that previously returned an empty transaction list with no
record). Those errors are counted only. Scan cursors still advance
on an empty result, whether that empty result is genuine or a failed
fetch.

## 2026-10-28 (lobo): annotations completed, Decision 1 confirmed

Hash confirmed Phase 3 Decision 1 (fix, then release) directly to
lobo, including the commentary-off interim step. Lobo completed the
annotation pass the same evening: the false-claims correction now
also opens `reports/report_2026-10-27_2256.md` (30 claim lines,
including fabricated rule citations) and
`reports/report_2026-10-29_0500.md` (55 claim lines; that run
predated the disable commit by minutes), and a retraction of the
94.9% figure opens `reports/report_2026-10-27_1900.md` and
`reports/report_2026-10-27_2021.md`. Full test suite at this head:
77 passed.

Still open from the packet's five fixes: fail-closed cursor
behaviour on fetch failure (counted today, not yet blocking),
the Tornado Cash label correction, and the deterministic
commentary filter that must exist before commentary is
re-enabled. A verification run was dispatched after this entry to
confirm a fresh report carries the coverage line and no AI
commentary.
