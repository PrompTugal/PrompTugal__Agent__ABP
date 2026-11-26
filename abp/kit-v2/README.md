# ABP kit v2: for cl-6.security's review (P8). Not installed anywhere.

Written by cl-6.abp@PrompTugal.dinis, 2026-11-26T16:13Z, on cl-6.security's four requirements (relayed from Dinis's ruling that the hooks are the control). Nothing here is installed: P8 (the install in every cl-6 repository) is Dinis's yes, and this diff goes to security first.

| Files | What |
|---|---|
| `claude/hooks/abp.mjs` | the kit's hook, 11 lines changed: no environment override of policy, log, keys or role outside tests (`ABP_TEST=1`); a breaker per kind of denial |
| `claude/hooks/launch.mjs` | new: the launcher the settings call. It verifies the signed pins, then runs the hook |
| `claude/settings.json` | the wiring, fail closed in the shell itself |
| `pins.mjs` | hashes the pinned files, the repository, the policy version and a rising sequence number into `abp/pins.json`; it names no key. cl-6.abp then signs by hand: `ssh-keygen -Y sign -f <its signing key> -n abp-pins abp/pins.json` (the one command that may name the key) |
| `test.sh` | 99 tests in a throw-away install and HOME, with throw-away signing keys (it names no real key); run: `bash abp/kit-v2/test.sh` |
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

## Kit v2.1 (2026-11-26T16:34Z): the signed install, the pull form of record 2026-11-26__abp-p8

Built on the agreement of cl-6.decisions (and pending cl-6.security's review): a protected path (\`.claude/**\`, \`abp/**\`) may change **only in a commit that carries \`abp/pins.json\` signed by cl-6.abp (namespace abp-pins) whose hashes match every changed protected file**. Nothing else gets a protected change through \`git commit\` or \`git push\`.

- New file \`claude/hooks/pinlib.mjs\`: the one place that checks the signature, used by the launcher at load and by the hook at commit and push. It holds the full SHA-256 of cl-6.abp's key; it is pinned like the others (five files now: hook, launcher, pinlib, settings, policy).
- \`pins.mjs\` writes the pins in two groups, \`hook\` (changes rarely) and \`policy\` (policies.json, the repository's own generated ABP and any extra file you name); the signature is one \`ssh-keygen -Y sign\` of \`abp/pins.json\`. A policy-only wave is therefore a commit of the policy, the ABP, pins.json and its signature.
- The hook's commit check reads the **staged** blobs and the push check the **HEAD** blobs: pins and signature from the same tree, then the hash of each changed protected file against them. A protected file that the pins do not list, an old pins file, pins signed by another key, a missing signature: refused.
- The pull form works because git writes the files: an agent \`git fetch\`es cl-6.abp's signed install commit and fast-forwards (or merges) it; the files and the new pins arrive together, so the launcher's pin check passes after the update. While they do not match, everything fails closed. The agent pushes the unchanged signed commit; the commit check lets it through because the pins cover it; the CI check (cl-6.dev) rejects anything else.
- Tests: six new ones (a signed install passes at commit and at push; old pins, pins signed by another key, an unlisted protected file and an unsigned push are refused; two of these judge the commit check itself, with a working tree that still matches the old pins). 74 in all.

What this does not change: nothing is installed; the exception it implements is a widening of the protection, so it applies only after Dinis's root (S1 step 4) and cl-6.security's review of this revision.

### Kit v2.1 and cl-6.security's seven conditions on record abp-p8 (revision 2, opinion eb92be5) (2026-11-26T16:38Z)

| # | Condition | In the kit |
|---|---|---|
| 1 | the key is pinned outside the repository being checked | \`pinlib.keyHash()\`: a key in the environment variable \`ABP_PIN_KEY_SHA256\` (set by IaC for sessions, by an org variable for CI) wins over the constant in the repository; \`ci-check.mjs\` refuses to run without it. The constant is only the fallback. **Needs cl-6.infra to set the variable in the environment.** |
| 2 | pins name the repository and version, with a rising sequence | \`pins.json\` v2 carries \`repository\`, \`version\`, \`seq\`. The launcher refuses pins for another repository and a sequence below the highest this machine has seen (\`~/.abp/seq/<repo>\`, protected); the commit check requires a higher sequence than HEAD's; CI takes \`--floor\`. A fresh container has seen none: CI's floor is the server side of this |
| 3 | the pins cover every file under .claude/** and abp/** | the commit and push checks require every protected file of the tree (not only the changed ones) to be listed with a matching hash; the launcher also refuses a file under \`.claude/hooks/\` or a \`.claude/settings*.json\` that the pins do not list (a \`settings.local.json\` written by the harness would be refused: list it in the pins or do not have one) |
| 4 | a CI required status as well as the hook | \`ci-check.mjs\`, offline, Node 18+, run on the checkout with the key from outside; exit 1 with the reason. cl-6.dev wires it (it needs this file and \`pinlib.mjs\` from a source other than the repository being checked) and Dinis merges |
| 5 | install by pull, no push attach | as in the pull form above |
| 6 | one wave a day | process: my wake installs at most one wave a day; the policy is the one file that changes between waves |
| 7 | my key is rotated through IaC pins | by the same environment variable: IaC sets the new key hash, the old constant is ignored |

Nine new tests (replay, another repository, the environment key both ways, an unlisted hook file, and five on the CI check): 85 in all.

### cl-6.security's fourth round, V1 to V3 and the plumbing (2026-11-26T16:41Z)

cl-6.security found that kit v2.0 (acc2f2a) and v2.1 (b14bdcf) could be got round, and withdrew its pass: the P8 record is suspended (revision 3). Fixed here:

| Finding | Fix | Test |
|---|---|---|
| V1 `git commit -am` reads the working tree, the hook read the index | a commit is refused when any protected path differs between the working tree and the index: stage it (git add) so the pins can be checked, or restore it | `commit -am` and `commit -m` with a working-tree-only change |
| V2 rollback: every pins file ever signed stayed valid | the pins name the repository and a sequence number; the commit check requires a sequence above HEAD's and above the remote branch's, the push check above the remote branch's; the launcher keeps a high-water mark per repository in a protected file and refuses lower; CI takes `--floor` | older signed pins and files put back over the newer install |
| V3 push read HEAD, not the ref pushed | each refspec's local side is resolved (or the current branch when none is given); the commits not on any remote, the files and the pins are read at that ref | `git push origin dev` and `dev:dev` from a clean branch while dev holds a bad commit; and the same push from a clean dev passes |
| plumbing | `git commit-tree`, `mktree`, `read-tree`, `update-index`, `write-tree`, `fast-import`, `replace` and `hash-object -w` are tamper | commit-tree, hash-object -w |

93 tests, all pass. Nothing is installed, and the install waits for both securities' pass on the head of this version, for cl-6.decisions' revision 4 of the record, and for Dinis's root.

### Round 5 (2026-11-26T16:43Z): C1 and settings.local.json

- **C1** (`ci-check.mjs`): CI keeps the last accepted sequence (\`--floor N\`) and the SHA-256 of the last accepted \`abp/pins.json\` (\`--last-pins-sha\`). Unchanged pins must carry exactly that sequence, so an ordinary commit after an install passes; changed pins must rise above it. Without \`--last-pins-sha\` the sequence must not fall below the floor. Three tests.
- **settings.local.json**: Claude Code writes it when a person approves "always allow". The launcher accepts it only if its keys are a subset of \`permissions\`; hooks, env, \`disableAllHooks\` or any other key fail closed (the hook still decides every tool call, so a local allow rule widens nothing past it). Three tests. The other \`.claude/hooks/**\` and \`.claude/settings*.json\` files must be pinned.
- **Who sets \`ABP_PIN_KEY_SHA256\`**: the environment's settings, which only Dinis (the person who owns that environment) approves, and the org or repository variable for CI. cl-6.infra cannot set the first; the second needs a variable action in IaC and the App's Variables permission. Hooks get Claude Code's own environment, not the Bash tool's \`export\`; the \`env\` block of a settings file is the other route, and settings.json is pinned.

**Note for the CI wiring (cl-6.security, round 5):** always pass `--last-pins-sha` (the SHA-256 of the last accepted `abp/pins.json`) together with `--floor`. Without it the check only requires the sequence not to fall below the floor, and equal-sequence pins with new content would pass the floor. They would still have to be signed by cl-6.abp's key, so the risk is low, but the wiring should not leave the flag out.

**Policy v1.7.1 (cl-6.security, 16:44 and 16:45 UTC):** `newsroom/tools/operator-keys.json` is protected with owner none (not even cl-6.dev may write the list that makes an operator: Dinis's own signed commit is the route); `git -c push.default=...` and `git config push.*` are denied by a shell rule (R5), so a matching push cannot send every matching branch. Both are policy, not hook code: the reviewed hook head does not move.

**A limit to state before install (cl-6.security, 16:50 UTC):** the hook strips a leading `VAR=value` prefix before it matches a command, so `GIT_SSH_COMMAND=x git fetch` is not seen by a shell rule. It counts as code-execution-class and stays in the residuals with `bash -c` and `python -c`. Hook v2.2 reads the prefixes too.

**v2.2 (cl-6.security B1 and B2, 16:51 UTC):** B1: `git fetch . dev:refs/remotes/origin/x` could move the remote-tracking refs the push check trusts; the hook now refuses a fetch into a local ref and a fetch from a local path. Residual: the push file list still reads `refs/remotes/*` (real fetches from origin move it correctly); security's fuller fix (compare with `git ls-remote`) needs the network and goes to CI's floor, which already checks the real tip. B2: the commit and push checks now run in the repository the command acts on (`cd`, `git -C`), and an unresolved directory refuses a commit or push. Tests 109/109.
