#!/usr/bin/env bash
# kit v2 tests, in a throw-away install (never in a real repository). usage: test.sh <path to the signing key>
set -uo pipefail; key=$1; here=$(cd "$(dirname "$0")" && pwd); pol=$here/../policies.json
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; mkdir -p $T/.claude/hooks $T/abp
cp $here/claude/hooks/*.mjs $T/.claude/hooks/; cp $here/claude/settings.json $T/.claude/; cp $pol $T/abp/policies.json
"$here/pin.sh" "$T" "$key" >/dev/null
export CLAUDE_PROJECT_DIR=$T ABP_TEST=1 ABP_ROLE=cl-6.dev ABP_LOG_DIR=$T/log; pass=0; fail=0
run(){ echo "$2" | node $T/.claude/hooks/launch.mjs pre-tool; }
chk(){ if [[ "$3" == *"$2"* ]]; then pass=$((pass+1)); echo "ok   $1"; else fail=$((fail+1)); echo "FAIL $1 :: $3" | cut -c1-200; fi; }
W='{"tool_name":"Write","tool_input":{"file_path":"'$T'/src/a.js"},"cwd":"'$T'"}'
chk "an allowed write passes (no output)" "" "$(run x "$W")"
[[ -z "$(run x "$W")" ]] && echo "     (empty = allow)"
chk "a write to .claude is blocked (tamper)" "permissionDecision" "$(run x '{"tool_name":"Write","tool_input":{"file_path":"'$T'/.claude/settings.json"},"cwd":"'$T'"}')"
chk "a shell write to .claude is blocked (tamper)" "permissionDecision" "$(run x '{"tool_name":"Bash","tool_input":{"command":"echo x > .claude/hooks/abp.mjs"},"cwd":"'$T'"}')"
chk "a write to abp/policies.json is blocked" "permissionDecision" "$(run x '{"tool_name":"Write","tool_input":{"file_path":"'$T'/abp/policies.json"},"cwd":"'$T'"}')"
chk "a push to main is blocked (R5)" "permissionDecision" "$(run x '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"cwd":"'$T'"}')"
chk "a session tool is blocked (R4)" "permissionDecision" "$(run x '{"tool_name":"mcp__claude-code-remote__create_session","tool_input":{}}')"
chk "reading a key is blocked (R8)" "permissionDecision" "$(run x '{"tool_name":"Read","tool_input":{"file_path":"'$HOME'/.ssh/id_rsa"}}')"
echo "// tampered" >> $T/.claude/hooks/abp.mjs
chk "a changed hook does not load (fail closed)" "fail closed" "$(run x "$W")"
chk "...but a read still passes" "" "$(run x '{"tool_name":"Read","tool_input":{"file_path":"'$T'/README.md"}}')"
cp $here/claude/hooks/abp.mjs $T/.claude/hooks/abp.mjs; "$here/pin.sh" "$T" "$key" >/dev/null
echo '{}' >> $T/abp/policies.json
chk "a changed policy does not load (fail closed)" "fail closed" "$(run x "$W")"
cp $pol $T/abp/policies.json; "$here/pin.sh" "$T" "$key" >/dev/null
sed -i 's/"v": 1/"v": 2/' $T/abp/pins.json
chk "edited pins without a new signature do not load" "fail closed" "$(run x "$W")"
"$here/pin.sh" "$T" "$key" >/dev/null
ssh-keygen -q -t ecdsa -N '' -f $T/other >/dev/null; rm -f $T/abp/pins.json.sig; ssh-keygen -Y sign -q -f $T/other -n abp-pins $T/abp/pins.json >/dev/null 2>&1
chk "pins signed by another key do not load" "fail closed" "$(run x "$W")"
"$here/pin.sh" "$T" "$key" >/dev/null
chk "no node at all: the shell prints the deny" "permissionDecision" "$(echo "$W" | env -i PATH=/nonexistent CLAUDE_PROJECT_DIR=$T /bin/bash -c "$(node -p 'require(process.argv[1]).hooks.PreToolUse[0].hooks[0].command' $T/.claude/settings.json)" 2>/dev/null)"
echo "passed $pass, failed $fail"
