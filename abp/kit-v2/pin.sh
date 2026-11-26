#!/usr/bin/env bash
# cl-6.abp only: pin the installed hook, launcher, settings and policy by SHA-256 and sign the pins (SSH signature, namespace abp-pins).
# usage: pin.sh <install root> <path to the signing key>   (the key path is never printed; the launcher accepts only cl-6.abp's published key)
set -euo pipefail
root=$1; key=$2; cd "$root"
node -e '
const fs=require("fs"),c=require("crypto"),f=[".claude/hooks/abp.mjs",".claude/hooks/launch.mjs",".claude/settings.json","abp/policies.json"];
const o={v:1,about:"SHA-256 of the files the hook may load; signed by cl-6.abp (abp-pins). A changed file does not load until cl-6.abp signs a new pins.json.",at:new Date().toISOString().slice(0,16)+"Z",files:Object.fromEntries(f.map(x=>[x,c.createHash("sha256").update(fs.readFileSync(x)).digest("hex")]))};
fs.writeFileSync("abp/pins.json",JSON.stringify(o,null,1)+"\n")'
rm -f abp/pins.json.sig; ssh-keygen -Y sign -q -f "$key" -n abp-pins abp/pins.json >/dev/null 2>&1
test -s abp/pins.json.sig && echo "pinned and signed: $(node -p 'Object.keys(require("./abp/pins.json").files).length') files"
