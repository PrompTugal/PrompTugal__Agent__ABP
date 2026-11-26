#!/usr/bin/env bash
# kit v2 tests, in a throw-away install and a throw-away HOME, with throw-away signing keys (it names no real key). usage: bash abp/kit-v2/test.sh
set -uo pipefail; here=$(cd "$(dirname "$0")" && pwd); pol=$here/../policies.json
T=$(mktemp -d); H=$(mktemp -d); trap 'rm -rf "$T" "$H"' EXIT; mkdir -p $T/.claude/hooks $T/abp $T/src $H/home/.abp/keys/cl-6.dev $H/home/.abp/log $T/k
ssh-keygen -q -t ecdsa -b 256 -N '' -f $T/k/a >/dev/null; ssh-keygen -q -t ecdsa -b 256 -N '' -f $T/k/b >/dev/null
fpa=$(ssh-keygen -e -m PKCS8 -f $T/k/a.pub | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
cp $here/claude/hooks/*.mjs $T/.claude/hooks/; cp $here/claude/settings.json $T/.claude/; cp $pol $T/abp/policies.json
sed -i "s/export const PIN_KEY_SHA256 = '[0-9a-f]*'/export const PIN_KEY_SHA256 = '$fpa'/" $T/.claude/hooks/pinlib.mjs   # the test copy trusts the throw-away key A
echo '{"label":"cl-6.dev@PrompTugal.dinis"}' > $H/home/.abp/keys/cl-6.dev/metadata.json
(cd $T && git init -q -b dev . && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m i) 2>/dev/null
pin(){ node $here/pins.mjs $T >/dev/null; rm -f $T/abp/pins.json.sig; ssh-keygen -Y sign -q -f $T/k/${1:-a} -n ${2:-abp-pins} $T/abp/pins.json >/dev/null 2>&1; mv $T/abp/pins.json.sig $T/abp/pins.json.sig 2>/dev/null; }
pin a
export HOME=$H/home CLAUDE_PROJECT_DIR=$T ABP_TEST=1 ABP_ROLE=cl-6.dev ABP_LOG_DIR=$T/log; pass=0; fail=0
run(){ echo "$1" | node $T/.claude/hooks/launch.mjs pre-tool; }
bash_(){ run '{"tool_name":"Bash","tool_input":{"command":'"$(node -p 'JSON.stringify(process.argv[1])' "$1")"'},"cwd":"'$T'"}'; }
deny(){ [[ "$2" == *permissionDecision* ]] && { pass=$((pass+1)); echo "ok   $1"; } || { fail=$((fail+1)); echo "FAIL $1 :: allowed"; }; }
denyk(){ [[ "$3" == *"$2"* ]] && { pass=$((pass+1)); echo "ok   $1"; } || { fail=$((fail+1)); echo "FAIL $1 :: $3" | cut -c1-220; }; }
allow(){ [[ -z "$2" ]] && { pass=$((pass+1)); echo "ok   $1"; } || { fail=$((fail+1)); echo "FAIL $1 :: $2" | cut -c1-220; }; }
W='{"tool_name":"Write","tool_input":{"file_path":"'$T'/src/a.js"},"cwd":"'$T'"}'
wr(){ run '{"tool_name":"Write","tool_input":{"file_path":"'$1'"},"cwd":"'$T'"}'; }
allow "an allowed write passes" "$(run "$W")"
deny  "a write to .claude is blocked (tamper)" "$(wr $T/.claude/settings.json)"
deny  "a shell write to .claude is blocked" "$(bash_ 'echo x > .claude/hooks/abp.mjs')"
deny  "a write to abp/policies.json is blocked" "$(wr $T/abp/policies.json)"
deny  "a push to main is blocked (R5)" "$(bash_ 'git push --force origin main')"
allow "F8: git push origin HEAD on dev is allowed" "$(bash_ 'git push origin HEAD')"
deny  "a session tool is blocked (R4)" "$(run '{"tool_name":"mcp__claude-code-remote__create_session","tool_input":{}}')"
deny  "reading a key is blocked (R8)" "$(run '{"tool_name":"Read","tool_input":{"file_path":"'$HOME'/.ssh/id_rsa"}}')"
echo "--- F1 identity"
deny  "F1: a write to another role's label" "$(wr $HOME/.abp/keys/cl-6.abp/metadata.json)"
deny  "F1: removing one's own label" "$(bash_ 'rm -rf ~/.abp/keys/cl-6.dev')"
export ABP_ROLE=cl-6.abp
deny  "F1: the owner has no exemption for .claude in a session" "$(wr $T/.claude/settings.json)"
export ABP_ROLE=cl-6.dev
mv $H/home/.abp/keys/cl-6.dev $T/labelbak
allow "F1: the first label (R14 bootstrap) is allowed while none exists" "$(bash_ 'mkdir -p ~/.abp/keys/cl-6.dev && printf x > ~/.abp/keys/cl-6.dev/metadata.json')"
mv $T/labelbak $H/home/.abp/keys/cl-6.dev 2>/dev/null; rm -rf $H/home/.abp/keys/cl-6.dev/cl-6.dev 2>/dev/null; [[ -f $H/home/.abp/keys/cl-6.dev/metadata.json ]] || { mkdir -p $H/home/.abp/keys/cl-6.dev; echo '{"label":"cl-6.dev@PrompTugal.dinis"}' > $H/home/.abp/keys/cl-6.dev/metadata.json; }
echo "--- F2 symlinks, G1 hard links"
deny  "F2: ln -s onto a protected file" "$(bash_ 'ln -s .claude/settings.json s.json')"
ln -s .claude/settings.json $T/s.json
deny  "F2: a write through an existing symlink" "$(wr $T/s.json)"
deny  "G1: cp -l of a protected file" "$(bash_ 'cp -l .claude/settings.json x.json')"
deny  "G1: cp -al of .claude" "$(bash_ 'cp -al .claude y')"
deny  "G1: rsync --link-dest=.claude" "$(bash_ 'rsync -a --link-dest=.claude a b')"
ln $T/.claude/settings.json $T/x.json
deny  "G1: a write to an existing hard link (nlink 2)" "$(wr $T/x.json)"
echo "--- F3 log, F4 cwd"
deny  "F3: deleting the audit log" "$(bash_ 'rm -rf ~/.abp/log')"
deny  "F3: deleting the salt" "$(bash_ 'rm ~/.abp/salt')"
deny  "F4: cd -- .claude && write" "$(bash_ 'cd -- .claude && echo x > settings.json')"
deny  "F4: pushd .claude && write" "$(bash_ 'pushd .claude && echo x > settings.json')"
deny  "F4: cd to a variable, then a write" "$(bash_ 'cd $X && echo x > f')"
deny  "F4: git -C .claude checkout" "$(bash_ 'git -C .claude checkout -- settings.json')"
echo "--- G2 writes the parser missed"
deny  "G2: >| redirect" "$(bash_ 'echo x >| .claude/settings.json')"
deny  "G2: dd of=" "$(bash_ 'dd of=.claude/settings.json')"
deny  "G2: a target built with \$(...)" "$(bash_ 'echo x > $(echo .claude)/settings.json')"
deny  "G2: find -delete" "$(bash_ 'find .claude -delete')"
deny  "G2: &> redirect" "$(bash_ 'echo x &> .claude/settings.json')"
echo "--- G3 git and archives"
deny  "G3: git checkout HEAD~3 -- .claude/settings.json" "$(bash_ 'git checkout HEAD~3 -- .claude/settings.json')"
deny  "G3: git restore --source=HEAD~3 .claude" "$(bash_ 'git restore --source=HEAD~3 .claude')"
deny  "G3: tar x into .claude" "$(bash_ 'tar xf a.tar -C .claude')"
deny  "G3: patch .claude/settings.json" "$(bash_ 'patch .claude/settings.json p.diff')"
mkdir -p $T/.claude && echo '{}' > $T/.claude/z.json; (cd $T && git add -f .claude/z.json)
denyk "G3: git commit with a protected path staged (R6)" "ABP R6" "$(bash_ 'git commit -m x')"; (cd $T && git rm -q --cached -f .claude/z.json) 2>/dev/null
allow "G3: git commit with nothing protected staged" "$(bash_ 'git commit -m "update the .claude notes"')"
echo "--- v2.1: the signed install leaves the machine only with signed pins"
T2=$(mktemp -d); mkdir -p $T2/.claude/hooks $T2/abp $T2/src; cp $T/.claude/hooks/*.mjs $T2/.claude/hooks/; cp $T/.claude/settings.json $T2/.claude/; cp $pol $T2/abp/policies.json
pin2(){ node $here/pins.mjs $T2 >/dev/null; rm -f $T2/abp/pins.json.sig; ssh-keygen -Y sign -q -f $T/k/${1:-a} -n abp-pins $T2/abp/pins.json >/dev/null 2>&1; }
pin2 a; git init -q --bare $T2.git; (cd $T2 && git init -q -b dev . && git remote add origin $T2.git && git add -A && git -c user.name=t -c user.email=t@t commit -q -m base && git push -q origin dev) 2>/dev/null
run2(){ CLAUDE_PROJECT_DIR=$T2 bash -c "echo '$1' | node $T2/.claude/hooks/launch.mjs pre-tool"; }
bash2(){ run2 '{"tool_name":"Bash","tool_input":{"command":'"$(node -p 'JSON.stringify(process.argv[1])' "$1")"'},"cwd":"'$T2'"}'; }
reset2(){ (cd $T2 && git reset -q --hard origin/dev && git clean -qfd) 2>/dev/null; }
echo '{"v":"new"}' > $T2/.claude/settings.json; pin2 a; (cd $T2 && git add -A)
allow "v2.1: a commit that changes a protected file WITH matching signed pins passes" "$(bash2 'git commit -m install')"
(cd $T2 && git -c user.name=t -c user.email=t@t commit -q -m install)
allow "v2.1: the push of that signed install passes" "$(bash2 'git push origin dev')"
(cd $T2 && git push -q origin dev); reset2
echo '{"v":"evil"}' > $T2/.claude/settings.json; (cd $T2 && git add -A)
deny  "v2.1: a protected change with the OLD pins is refused (by the launcher, which fails closed on a changed pinned file, or by the commit check)" "$(bash2 'git commit -m x')"; reset2
echo '{"v":"evil"}' > $T2/.claude/settings.json; pin2 b; (cd $T2 && git add -A)
deny  "v2.1: a protected change with pins signed by another key is refused" "$(bash2 'git commit -m x')"; reset2
echo '{"v":"new2"}' > $T2/.claude/settings.json; echo '{}' > $T2/.claude/extra.json; pin2 a; (cd $T2 && git add -f -A)
denyk "v2.1: a protected file that the pins do not list is refused even with valid pins" "ABP R6" "$(bash2 'git commit -m x')"; reset2
# the commit check itself, with a working tree that still matches the old pins (so the launcher passes and the staged change is what is judged)
cp $T2/.claude/settings.json $T2/settings.good; echo '{"v":"evil"}' > $T2/.claude/settings.json; (cd $T2 && git add .claude/settings.json); cp $T2/settings.good $T2/.claude/settings.json
denyk "v2.1: a staged protected change that the committed pins do not cover is refused by the commit check (R6)" "ABP R6" "$(bash2 'git commit -m x')"; reset2
echo '{"v":"new3"}' > $T2/.claude/settings.json; cp $T2/abp/pins.json $T2/pins.old; cp $T2/abp/pins.json.sig $T2/pins.old.sig; pin2 b; (cd $T2 && git add -A .claude abp); cp $T2/.claude/settings.json $T2/new3.json; (cd $T2 && git show HEAD:.claude/settings.json > .claude/settings.json && git show HEAD:abp/pins.json > abp/pins.json && git show HEAD:abp/pins.json.sig > abp/pins.json.sig)
denyk "v2.1: staged pins signed by another key do not cover a staged change (R6)" "ABP R6" "$(bash2 'git commit -m x')"; reset2
echo '{"v":"evil"}' > $T2/.claude/settings.json; (cd $T2 && git add -A && git -c user.name=t -c user.email=t@t commit -q -m unsigned)
deny  "v2.1: the push of an unsigned protected change is refused" "$(bash2 'git push origin dev')"; rm -rf $T2 $T2.git
echo "--- F7 and G4 and G5 secrets"
deny  "F7: awk on a private key" "$(bash_ 'awk 1 ~/.ssh/id_ed25519')"
deny  "F7: sed on a private key" "$(bash_ 'sed -n p ~/.ssh/id_rsa')"
deny  "G4: git diff --no-index on a key" "$(bash_ 'git diff --no-index /dev/null ~/.ssh/id_ed25519')"
deny  "G4: git hash-object -w on a key" "$(bash_ 'git hash-object -w ~/.ssh/id_ed25519')"
deny  "G4: a kit script given a key path" "$(bash_ 'bash abp/kit-v2/pin.sh . ~/.ssh/id_ed25519')"
deny  "G4: rewriting a kit script (abp/** at every depth)" "$(wr $T/abp/kit-v2/pin.sh)"
allow "ssh-keygen -Y sign on a key is allowed" "$(bash_ 'ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n abp-pins abp/pins.json')"
allow "ssh-keygen -y on a key is allowed" "$(bash_ 'ssh-keygen -y -f /tmp/k.pem')"
deny  "G5: cp -r of the key store" "$(bash_ 'cp -r ~/.abp/keys /tmp/k')"
denyk "nit: mkdir under ~/.abp/keys is R6 (tamper), not R8 (secret)" "ABP R6" "$(bash_ 'mkdir -p ~/.abp/keys/cl-6.abp')"
echo "--- H1 searching and listing a directory that holds secrets"
mkdir -p $HOME/.ssh $HOME/.abp/keys; echo dummy > $HOME/.ssh/dummy
deny  "H1: Grep on ~/.ssh" "$(run '{"tool_name":"Grep","tool_input":{"pattern":"x","path":"'$HOME'/.ssh"},"cwd":"'$T'"}')"
deny  "H1: Grep on ~/.abp/keys" "$(run '{"tool_name":"Grep","tool_input":{"pattern":"x","path":"'$HOME'/.abp/keys"},"cwd":"'$T'"}')"
deny  "H1: Grep on the home directory" "$(run '{"tool_name":"Grep","tool_input":{"pattern":"x","path":"'$HOME'"},"cwd":"'$T'"}')"
deny  "H1: Glob on ~/.abp/keys" "$(run '{"tool_name":"Glob","tool_input":{"pattern":"*","path":"'$HOME'/.abp/keys"},"cwd":"'$T'"}')"
deny  "H1: Glob with an absolute pattern into ~/.ssh" "$(run '{"tool_name":"Glob","tool_input":{"pattern":"'$HOME'/.ssh/*"},"cwd":"'$T'"}')"
deny  "H1: LS of ~/.ssh" "$(run '{"tool_name":"LS","tool_input":{"path":"'$HOME'/.ssh"},"cwd":"'$T'"}')"
allow "H1: Grep in the repository still passes" "$(run '{"tool_name":"Grep","tool_input":{"pattern":"x","path":"'$T'/src"},"cwd":"'$T'"}')"
allow "H1: Grep with no path (the repository) still passes" "$(run '{"tool_name":"Grep","tool_input":{"pattern":"x"},"cwd":"'$T'"}')"
echo "--- H2 targets the parser cannot read"
deny  "H2: quotes inside a word" "$(bash_ 'echo x > .cl""aude/settings.json')"
deny  "H2: ? in a target" "$(bash_ 'echo x > .clau?e/settings.json')"
deny  "H2: * in a target" "$(bash_ 'echo x > .cla*/settings.json')"
deny  "H2: cd to a glob, then a write" "$(bash_ 'cd .c* && echo x > settings.json')"
deny  "H2: exec 3> (an fd-numbered redirect)" "$(bash_ 'exec 3>.claude/settings.json')"
allow "H2: 2>&1 and 2>/dev/null still pass" "$(bash_ 'node --version 2>&1 | head -1; ls 2>/dev/null')"
echo "--- pins, fail closed"
echo "// tampered" >> $T/.claude/hooks/abp.mjs
denyk "a changed hook does not load" "fail closed" "$(run "$W")"
allow "...but a read still passes" "$(run '{"tool_name":"Read","tool_input":{"file_path":"'$T'/README.md"}}')"
cp $here/claude/hooks/abp.mjs $T/.claude/hooks/abp.mjs; pin a
echo '{}' >> $T/abp/policies.json
denyk "a changed policy does not load" "fail closed" "$(run "$W")"
cp $pol $T/abp/policies.json; pin a
sed -i 's/"v": 1/"v": 2/' $T/abp/pins.json
denyk "edited pins without a new signature do not load" "fail closed" "$(run "$W")"
pin b
denyk "pins signed by another key do not load (F5: the full key hash)" "fail closed" "$(run "$W")"
pin a wrong-namespace
denyk "a signature in another namespace does not load (F6)" "fail closed" "$(run "$W")"
pin a
r=$(echo "$W" | env -i PATH=/nonexistent CLAUDE_PROJECT_DIR=$T /bin/bash -c "$(node -p 'require(process.argv[1]).hooks.PreToolUse[0].hooks[0].command' $T/.claude/settings.json)" 2>/dev/null)
deny  "no node at all: the shell prints the deny" "$r"
echo "passed $pass, failed $fail"
