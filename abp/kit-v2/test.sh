#!/usr/bin/env bash
# kit v2 tests, in a throw-away install and a throw-away HOME, with throw-away signing keys (it names no real key). usage: bash abp/kit-v2/test.sh
set -uo pipefail; here=$(cd "$(dirname "$0")" && pwd); pol=$here/../policies.json
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; mkdir -p $T/.claude/hooks $T/abp $T/src $T/home/.abp/keys/cl-6.dev $T/home/.abp/log $T/k
ssh-keygen -q -t ecdsa -b 256 -N '' -f $T/k/a >/dev/null; ssh-keygen -q -t ecdsa -b 256 -N '' -f $T/k/b >/dev/null
fpa=$(ssh-keygen -e -m PKCS8 -f $T/k/a.pub | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
cp $here/claude/hooks/*.mjs $T/.claude/hooks/; cp $here/claude/settings.json $T/.claude/; cp $pol $T/abp/policies.json
sed -i "s/const PIN_KEY_SHA256 = '[0-9a-f]*'/const PIN_KEY_SHA256 = '$fpa'/" $T/.claude/hooks/launch.mjs   # the test copy trusts the throw-away key A
echo '{"label":"cl-6.dev@PrompTugal.dinis"}' > $T/home/.abp/keys/cl-6.dev/metadata.json
(cd $T && git init -q -b dev . && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m i) 2>/dev/null
pin(){ node $here/pins.mjs $T >/dev/null; rm -f $T/abp/pins.json.sig; ssh-keygen -Y sign -q -f $T/k/${1:-a} -n ${2:-abp-pins} $T/abp/pins.json >/dev/null 2>&1; mv $T/abp/pins.json.sig $T/abp/pins.json.sig 2>/dev/null; }
pin a
export HOME=$T/home CLAUDE_PROJECT_DIR=$T ABP_TEST=1 ABP_ROLE=cl-6.dev ABP_LOG_DIR=$T/log; pass=0; fail=0
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
mv $T/home/.abp/keys/cl-6.dev $T/labelbak
allow "F1: the first label (R14 bootstrap) is allowed while none exists" "$(bash_ 'mkdir -p ~/.abp/keys/cl-6.dev && printf x > ~/.abp/keys/cl-6.dev/metadata.json')"
mv $T/labelbak $T/home/.abp/keys/cl-6.dev 2>/dev/null; rm -rf $T/home/.abp/keys/cl-6.dev/cl-6.dev 2>/dev/null; [[ -f $T/home/.abp/keys/cl-6.dev/metadata.json ]] || { mkdir -p $T/home/.abp/keys/cl-6.dev; echo '{"label":"cl-6.dev@PrompTugal.dinis"}' > $T/home/.abp/keys/cl-6.dev/metadata.json; }
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
