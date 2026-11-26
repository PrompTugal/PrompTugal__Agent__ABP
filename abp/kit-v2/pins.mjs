#!/usr/bin/env node
// Writes abp/pins.json: the SHA-256 of the files the hook may load, in two groups (the hook changes rarely, the policy often).
// It names no key. cl-6.abp then signs it, by hand:   ssh-keygen -Y sign -f <its signing key> -n abp-pins abp/pins.json   (writes abp/pins.json.sig)
// usage: node pins.mjs <install root> [extra file ...]   (extra: the generated ABP of the repository's agent, abp/tools.mjs, ...)
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto'
const root = path.resolve(process.argv[2] || '.'), extra = process.argv.slice(3)
const hook = ['.claude/hooks/abp.mjs', '.claude/hooks/launch.mjs', '.claude/hooks/pinlib.mjs', '.claude/settings.json'], policy = ['abp/policies.json', ...extra]
const h = x => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, x))).digest('hex')
const o = { v: 1, about: 'SHA-256 of the files the hook may load; signed by cl-6.abp (abp-pins). A changed file does not load, and does not leave the machine at git commit or git push, until cl-6.abp signs a new pins.json.', at: new Date().toISOString().slice(0, 16) + 'Z', groups: { hook, policy }, files: Object.fromEntries([...hook, ...policy].map(x => [x, h(x)])) }
fs.writeFileSync(path.join(root, 'abp/pins.json'), JSON.stringify(o, null, 1) + '\n'); console.log('pins written for', Object.keys(o.files).length, 'files; now sign them')
