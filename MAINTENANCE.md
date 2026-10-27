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
deferred 3, exactly as the partial-run note records. A final
confirmation run under the 60-minute timeout was dispatched as run
40565910452; its conclusion will be appended here when it lands.

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
from 3 to a single informational notice from GitHub. PR #8 awaits
the owner's review and merge; merging data is the owner's call,
not the agent's.
