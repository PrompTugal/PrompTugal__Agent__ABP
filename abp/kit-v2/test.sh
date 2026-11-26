#!/usr/bin/env bash
# kit v2 tests, in a throw-away install and a throw-away HOME (never in a real repository). usage: test.sh <path to the signing key>
set -uo pipefail; key=$1; here=$(cd "$(dirname "$0")" && pwd); pol=$here/../policies.json
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; mkdir -p $T/.claude/hooks $T/abp $T/src $T/home/.abp/keys/cl-6.dev $T/home/.abp/log
cp $here/claude/hooks/*.mjs $T/.claude/hooks/; cp $here/claude/settings.json $T/.claude/; cp $pol $T/abp/policies.json
echo '{"label":"cl-6.dev@PrompTugal.dinis"}' > $T/home/.abp/keys/cl-6.dev/metadata.json
(cd $T && git init -q -b dev . && git remote add origin https://github.com/PrompTugal/x && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m i) 2>/dev/null
"$here/pin.sh" "$T" "$key" >/dev/null
export HOME=$T/home CLAUDE_PROJECT_DIR=$T ABP_TEST=1 ABP_ROLE=cl-6.dev ABP_LOG_DIR=$T/log; pass=0; fail=0
run(){ echo "$1" | node $T/.claude/hooks/launch.mjs pre-tool; }
bash_(){ run '{"tool_name":"Bash","tool_input":{"command":"'"$1"'"},"cwd":"'$T'"}'; }
deny(){ [[ "$2" == *permissionDecision* ]] && { pass=$((pass+1)); echo "ok   $1"; } || { fail=$((fail+1)); echo "FAIL $1 :: allowed"; }; }
allow(){ [[ -z "$2" ]] && { pass=$((pass+1)); echo "ok   $1"; } || { fail=$((fail+1)); echo "FAIL $1 :: $2" | cut -c1-200; }; }
W='{"tool_name":"Write","tool_input":{"file_path":"'$T'/src/a.js"},"cwd":"'$T'"}'
allow "an allowed write passes" "$(run "$W")"
deny  "a write to .claude is blocked (tamper)" "$(run '{"tool_name":"Write","tool_input":{"file_path":"'$T'/.claude/settings.json"},"cwd":"'$T'"}')"
deny  "a shell write to .claude is blocked" "$(bash_ 'echo x > .claude/hooks/abp.mjs')"
deny  "a write to abp/policies.json is blocked" "$(run '{"tool_name":"Write","tool_input":{"file_path":"'$T'/abp/policies.json"},"cwd":"'$T'"}')"
deny  "a push to main is blocked (R5)" "$(bash_ 'git push --force origin main')"
allow "F8: git push origin HEAD on dev is allowed" "$(bash_ 'git push origin HEAD')"
deny  "a session tool is blocked (R4)" "$(run '{"tool_name":"mcp__claude-code-remote__create_session","tool_input":{}}')"
deny  "reading a key is blocked (R8)" "$(run '{"tool_name":"Read","tool_input":{"file_path":"'$HOME'/.ssh/id_rsa"}}')"
echo "--- F1: identity"
deny  "F1: a write to another role's label is blocked" "$(run '{"tool_name":"Write","tool_input":{"file_path":"'$HOME'/.abp/keys/cl-6.abp/metadata.json"},"cwd":"'$T'"}')"
deny  "F1: removing one's own label is blocked" "$(bash_ 'rm -rf ~/.abp/keys/cl-6.dev')"
export ABP_ROLE=cl-6.abp
deny  "F1: the owner has no exemption for .claude in a session" "$(run '{"tool_name":"Write","tool_input":{"file_path":"'$T'/.claude/settings.json"},"cwd":"'$T'"}')"
export ABP_ROLE=cl-6.dev
mv $T/home/.abp/keys/cl-6.dev $T/labelbak
allow "F1: the first label (R14 bootstrap) is allowed while none exists" "$(bash_ 'mkdir -p ~/.abp/keys/cl-6.dev && printf x > ~/.abp/keys/cl-6.dev/metadata.json')"
mv $T/labelbak $T/home/.abp/keys/cl-6.dev
echo "--- F2: symlinks"
deny  "F2: ln -s onto a protected file is blocked" "$(bash_ 'ln -s .claude/settings.json s.json')"
ln -s .claude/settings.json $T/s.json
deny  "F2: a write through an existing symlink is blocked" "$(run '{"tool_name":"Write","tool_input":{"file_path":"'$T'/s.json"},"cwd":"'$T'"}')"
echo "--- F3: the log"
deny  "F3: deleting the audit log is blocked" "$(bash_ 'rm -rf ~/.abp/log')"
deny  "F3: deleting the salt is blocked" "$(bash_ 'rm ~/.abp/salt')"
echo "--- F4: working directory"
deny  "F4: cd -- .claude && write" "$(bash_ 'cd -- .claude && echo x > settings.json')"
deny  "F4: pushd .claude && write" "$(bash_ 'pushd .claude && echo x > settings.json')"
deny  "F4: cd to a variable, then a write" "$(bash_ 'cd $X && echo x > f')"
deny  "F4: git -C .claude checkout" "$(bash_ 'git -C .claude checkout -- settings.json')"
echo "--- F7: secrets, whatever the verb"
deny  "F7: awk on a private key" "$(bash_ 'awk 1 ~/.ssh/id_ed25519')"
deny  "F7: sed on a private key" "$(bash_ 'sed -n p ~/.ssh/id_rsa')"
allow "F7: ssh-keygen -y on a key is allowed (signing and public halves)" "$(bash_ 'ssh-keygen -y -f /tmp/k.pem')"
echo "--- pins and fail closed"
echo "// tampered" >> $T/.claude/hooks/abp.mjs
[[ "$(run "$W")" == *"fail closed"* ]] && { pass=$((pass+1)); echo "ok   a changed hook does not load"; } || { fail=$((fail+1)); echo "FAIL changed hook"; }
allow "...but a read still passes" "$(run '{"tool_name":"Read","tool_input":{"file_path":"'$T'/README.md"}}')"
cp $here/claude/hooks/abp.mjs $T/.claude/hooks/abp.mjs; "$here/pin.sh" "$T" "$key" >/dev/null
echo '{}' >> $T/abp/policies.json
[[ "$(run "$W")" == *"fail closed"* ]] && { pass=$((pass+1)); echo "ok   a changed policy does not load"; } || { fail=$((fail+1)); echo "FAIL changed policy"; }
cp $pol $T/abp/policies.json; "$here/pin.sh" "$T" "$key" >/dev/null
sed -i 's/"v": 1/"v": 2/' $T/abp/pins.json
[[ "$(run "$W")" == *"fail closed"* ]] && { pass=$((pass+1)); echo "ok   edited pins without a new signature do not load"; } || { fail=$((fail+1)); echo "FAIL edited pins"; }
"$here/pin.sh" "$T" "$key" >/dev/null
ssh-keygen -q -t ecdsa -N '' -f $T/other >/dev/null; rm -f $T/abp/pins.json.sig; ssh-keygen -Y sign -q -f $T/other -n abp-pins $T/abp/pins.json >/dev/null 2>&1
[[ "$(run "$W")" == *"fail closed"* ]] && { pass=$((pass+1)); echo "ok   pins signed by another key do not load (F5: the full key hash)"; } || { fail=$((fail+1)); echo "FAIL other key"; }
"$here/pin.sh" "$T" "$key" >/dev/null
rm -f $T/abp/pins.json.sig; ssh-keygen -Y sign -q -f "$key" -n wrong-namespace $T/abp/pins.json >/dev/null 2>&1; mv $T/abp/pins.json.sig $T/abp/pins.json.sig 2>/dev/null
[[ "$(run "$W")" == *"fail closed"* ]] && { pass=$((pass+1)); echo "ok   a signature in another namespace does not load (F6)"; } || { fail=$((fail+1)); echo "FAIL namespace"; }
"$here/pin.sh" "$T" "$key" >/dev/null
r=$(echo "$W" | env -i PATH=/nonexistent CLAUDE_PROJECT_DIR=$T /bin/bash -c "$(node -p 'require(process.argv[1]).hooks.PreToolUse[0].hooks[0].command' $T/.claude/settings.json)" 2>/dev/null)
deny  "no node at all: the shell prints the deny" "$r"
echo "passed $pass, failed $fail"
