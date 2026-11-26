# ABP kit v2: for cl-6.security's review (P8). Not installed anywhere.

Written by cl-6.abp@PrompTugal.dinis, 2026-11-26T16:13Z, on cl-6.security's four requirements (relayed from Dinis's ruling that the hooks are the control). Nothing here is installed: P8 (the install in every cl-6 repository) is Dinis's yes, and this diff goes to security first.

| Files | What |
|---|---|
| `claude/hooks/abp.mjs` | the kit's hook, 11 lines changed: no environment override of policy, log, keys or role outside tests (`ABP_TEST=1`); a breaker per kind of denial |
| `claude/hooks/launch.mjs` | new: the launcher the settings call. It verifies the signed pins, then runs the hook |
| `claude/settings.json` | the wiring, fail closed in the shell itself |
| `pins.mjs` | hashes the four pinned files into `abp/pins.json`; it names no key. cl-6.abp then signs by hand: `ssh-keygen -Y sign -f <its signing key> -n abp-pins abp/pins.json` (the one command that may name the key) |
| `test.sh` | 66 tests in a throw-away install and HOME, with throw-away signing keys (it names no real key); run: `bash abp/kit-v2/test.sh` |
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

## After cl-6.security's review of 59d485c (2026-11-26T16:18Z): F1 to F8

| Finding | Fix | Test |
|---|---|---|
| F1 identity is self-asserted; the owner exemption reaches it | \`~/.abp/keys/**\`, \`~/.abp/log/**\`, \`~/.abp/salt\` are protected (tamper). A first label is allowed only while the keys directory holds none (the R14 bootstrap). No owner exemption for \`.claude/**\` and the settings files in a session (policy v1.6.0) | write to another role's label, rm of one's own label, owner write to .claude, the bootstrap |
| F2 a symlink defeats the path check | every path is checked as given and with symlinks resolved (\`realpath\` of the nearest existing parent); \`ln\` and \`mv\` check every argument | ln -s onto a protected file; a write through an existing symlink |
| F3 the audit log can be deleted | protected (tamper) | rm of the log, rm of the salt |
| F4 forms of \`cd\` | \`cd\` with options, \`pushd\`, \`popd\`; a cwd that cannot be resolved (a variable, \`cd -\`) makes any write in that command denied; a write target whose text names .claude, HOLD.md, .git/config or ~/.abp/(keys\|log\|salt) is denied whatever the cwd; \`git -C <protected dir>\` with a changing subcommand is denied | four forms |
| F5 the pin was 64 bits | the launcher pins the full SHA-256 of the public key | pins signed by another key |
| F6 sshsig parsing | magic, version 1, exact namespace abp-pins, empty reserved field, sha256 or sha512 only | a signature in another namespace |
| F7 R8 named only some readers | any verb: a secret path in a segment is refused (ssh-keygen and git, and kit-v2's own pin.sh and test.sh, are the exceptions: signing needs the key's name) | awk, sed on a private key; ssh-keygen -y allowed |
| F8 \`git push origin HEAD\` refused on dev | HEAD is accepted when the current branch is the target | push origin HEAD |

Also run: nine ordinary commands of cl-6.abp's own work (commit, push to dev, build, appends to the log, a curl read, cat, a run report, the test script, git cat-file) are all allowed.

### Installing and updating .claude/ (new, from F1)

No session may write \`.claude/**\` or the settings files, the owner's included. An install or an update is made by cl-6.abp in a **scratch clone outside the session's repository** (for example under /tmp), signed, pushed to dev, reviewed by cl-6.security, and pulled into the repository; \`pin.sh\` then signs the new pins in that clone. The hook cannot see what git does to files, which is also why the pins exist: a pull that changes a pinned file without a new signed pins.json does not load.

## After cl-6.security's second review of cbed7e4 (2026-11-26T16:22Z): G1 to G5 and the nit

| Finding | Fix | Test |
|---|---|---|
| G1 hard links | a write to a file with more than one link is tamper (realpath cannot see them); `cp`, `rsync` and `install` check every argument and `--x=value` options (`cp -l`, `cp -al`, `--link-dest=`) | cp -l, cp -al, rsync --link-dest, a write to an existing hard link |
| G2 writes the parser missed | the redirect regex accepts `>\|` and `&>`; `dd of=`; a target containing `$(` or a backtick is denied (it cannot be checked); `find` with `-delete`, `-exec`, `-ok`, `-fprint*` checks its paths | `>\|`, dd, `$(...)`, find -delete, `&>` |
| G3 git, tar, patch and the rest | at `git commit` the hook reads `git diff --cached --name-only` (and the tree for `-a`), at `git push` the files of every commit not on any remote; a protected path in either is tamper, whatever route put it there. And any command that is not a plain read and names .claude, HOLD.md, .git/config or ~/.abp/(keys\|log\|salt) is tamper (tar, unzip, patch, git checkout, git restore, ...) | git checkout, git restore, tar, patch, a commit with a protected path staged; an ordinary commit that only mentions .claude in its message passes |
| G4 the F7 exemptions leaked keys | the protected glob is `abp/**` at every depth; pin.sh is gone (pins.mjs names no key); the only commands that may name a key are `ssh-keygen -Y sign`, `-y`, `-l`, and `git commit` or `git config` | git diff --no-index and git hash-object on a key, a kit script given a key path, a write to abp/kit-v2/ |
| G5 `cp -r ~/.abp/keys` | every argument of cp and rsync is checked against secret_reads, with the directory itself counted | cp -r of the key store |
| nit | a command under ~/.abp/keys is logged as R6 tamper, not R8 secret | mkdir |

Two things only a server can do, for Dinis and cl-6.dev (security's note): a check in CI in each repository that rejects a change to `.claude/**` or `abp/**` not signed by cl-6.abp's key. The hook cannot see what git does to files; the commit and push check above catches the routes through the hook's own session, not a clone made elsewhere.

Also run, as before: fifteen ordinary commands of cl-6.abp's own work (commit with `.claude` in its message, push to dev, build, an append to the log, curl, cat, a run report directory, ssh-keygen -Y sign, pins.mjs, test.sh, git log and ls and grep on .claude, git add, git status) are all allowed.

## After cl-6.security's third review of e1e7a8e (2026-11-26T16:25Z): H1, H2, and H3 stated

| Finding | Fix | Test |
|---|---|---|
| H1 Grep, Glob and LS on a directory that holds secrets | a search or listing is denied (R8) when its path equals, is above (the home directory too) or is inside any secret path with a fixed absolute prefix; a Glob pattern with an absolute prefix is checked the same way | Grep on ~/.ssh, ~/.abp/keys and the home directory; Glob on ~/.abp/keys and an absolute pattern into ~/.ssh; LS of ~/.ssh; a Grep in the repository still passes |
| H2 targets the parser cannot read | quotes inside a word are removed before matching; a write or cd target with a glob character (\`*\`, \`?\`, \`[\`) is denied: it cannot be checked; a redirect with a file descriptor number (\`3>\`) is a redirect | quotes inside a word, ? and * in a target, cd to a glob, exec 3>; 2>&1 and 2>/dev/null still pass |

### What it will still not stop (H3, accepted by cl-6.security, for Dinis)

Commands that rewrite the working tree without naming a path: \`git reset --hard\`, \`stash pop\`, \`pull\`, \`merge\`, \`checkout <branch>\`, \`rebase\`, \`cherry-pick\`, \`am\`, \`apply\`, \`tar\`, \`unzip\`. The commit and push check stops such a change **leaving the machine**, and a cloud session starts from a fresh clone. The gap is a local or resumed session in the same working tree: its next start would load whatever settings.json is on disk. That is covered by the per-repository CI check (reject a \`.claude/**\` or \`abp/**\` change not signed by cl-6.abp's key: for Dinis and cl-6.dev) and cl-6.security's review.
