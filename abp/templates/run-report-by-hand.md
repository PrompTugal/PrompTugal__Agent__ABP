# A run report without the hooks (R10)

Use this only where the hook kit is not installed in your session. The hooks write the log a run report is built from; without them you write what you know, honestly, and say so.

1. Copy `abp/templates/run-report-by-hand.json` (from https://github.com/PrompTugal/PrompTugal__Agent__ABP/blob/dev/abp/templates/run-report-by-hand.json) to `runs/<your agent name>/<run>.json` in your own home repository (granted: `runs/{role}/**`). Times from `date -u`.
2. Fill `agent`, `run`, `started`, `ended`, `line` (start it with "HAND-WRITTEN, hooks not installed") and `policy.version` and `policy.sha256` (from `abp/policies.json` in PrompTugal__Agent__ABP). Leave `policies_instrumented` empty: no hook measured anything.
3. `breaches`: every thing you know you did outside your grant, one entry each (`kind`, `what`, `rule`). If you know of none, leave it empty and say in `line` that it is by your own account.
4. Do not invent counts. Leave the counters at 0 and say in `line` that they are unmeasured.
4a. **Never write request text.** `requests` stays an empty list, or at most `{"t": <time>, "chars": <length>}` per request: no heads, no excerpts, no quotes of what the owner typed or of an uploaded file, and no name of a private person anywhere in the report (R8, R12). The hook's reports hold a length and a keyed hash only; a hand-written one holds less. A report that carries text goes to cl-6.security as a finding, and its text is removed from the branch.
5. Commit it alone or with your last commit, signed, with your Agent: and Claude-Session: trailers. The hourly review treats a hand-written report as filed (R10 kept) and as unverified.

Installing the hooks in your home repository (`.claude/settings.json`, `.claude/hooks/abp.mjs`, `abp/policies.json`, `abp/tools.mjs`) is cl-6.abp's, and needs Dinis's word: those paths are protected, and cl-6.abp is not attached to your repository.
