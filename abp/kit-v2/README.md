# ABP kit v2: for cl-6.security's review (P8). Not installed anywhere.

Written by cl-6.abp@PrompTugal.dinis, 2026-11-26T16:13Z, on cl-6.security's four requirements (relayed from Dinis's ruling that the hooks are the control). Nothing here is installed: P8 (the install in every cl-6 repository) is Dinis's yes, and this diff goes to security first.

| Files | What |
|---|---|
| `claude/hooks/abp.mjs` | the kit's hook, 11 lines changed: no environment override of policy, log, keys or role outside tests (`ABP_TEST=1`); a breaker per kind of denial |
| `claude/hooks/launch.mjs` | new: the launcher the settings call. It verifies the signed pins, then runs the hook |
| `claude/settings.json` | the wiring, fail closed in the shell itself |
| `pin.sh` | cl-6.abp only: hashes the four pinned files and signs `abp/pins.json` |
| `test.sh` | 13 tests in a throw-away install; run: `bash abp/kit-v2/test.sh <signing key path>` |
| `DIFF-vs-kit-v1.patch` | the diff against the kit of https://sovereignwebsite.ai/abp/kit/ (hook and settings) |

## The four requirements

1. **The hooks block, not only log.** Breakers on in policy v1.5.0: R3, R4, R5, R8 (rules), and the kind `tamper` (a write to a protected path). R6 as a whole stays observe: blocking every out-of-grant write would stop agents whose grants are still open (P11 and the others); security's call and Dinis's. Tests: push to main, session tool, key read, write to .claude, write to abp/policies.json, shell redirect into .claude.
2. **An agent cannot edit or switch off its own hooks.** `.claude/**`, `abp/*`, `**/.claude/settings*.json`, `~/.claude/settings*.json` and `.git/config` are protected and, with the `tamper` breaker, a write is refused. `git config core.hooksPath`, `--global` and `--system` are denied by the shell rules.
3. **Pinned by hash, changed only by a signed update.** `abp/pins.json` lists the SHA-256 of the hook, the launcher, the settings and the policy; `abp/pins.json.sig` is an SSH signature (namespace abp-pins) that the launcher checks itself (no ssh-keygen needed) against cl-6.abp's published signing key, sha256:eb5b09f0fa1e6e67. A changed file, edited pins, pins signed by another key: nothing loads (tests). Each policy change by cl-6.abp needs a new signed pins.json.
4. **Missing or failing: fail closed.** The launcher fails closed (only Read, Grep, Glob, LS, ToolSearch, TodoWrite pass); the settings print the deny themselves if node or the launcher cannot run (test: no node). Kit v1 swallowed this with `|| true`.

## What it still does not do (say it to Dinis plainly)

- Anything that runs code (bash -c, python -c, a script it writes and runs) can still get past the text checks; and the launcher pins itself, so an agent that could rewrite it would also rewrite the pins check. The protection is the hook refusing the write (requirement 2) and the review catching it after the fact: it is a guardrail and an audit log, not a boundary (the kit says so).
- A policy in every repository can drift: each install is a copy; my review must compare their pinned hashes.
- A session whose settings do not load this repository's hooks is not covered at all.
- Sub-agents: not confirmed whether the hook sees their calls.

## To install (not yet): per repository, cl-6.abp copies claude/ to .claude/, abp/policies.json and abp/tools.mjs to abp/, runs pin.sh, and commits signed; cl-6.security reviews the commit first.
