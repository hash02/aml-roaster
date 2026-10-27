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

**Verification.** All 66 existing tests pass. A verification scan
run with these changes has been dispatched; its conclusion will
be appended here when it lands.
