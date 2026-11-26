#!/usr/bin/env node
// Writes abp/pins.json: the SHA-256 of the four pinned files of an install. It names no key. cl-6.abp then signs it, by hand:
//   ssh-keygen -Y sign -f <its signing key> -n abp-pins abp/pins.json        (writes abp/pins.json.sig)
// usage: node pins.mjs <install root>
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto'
const root = path.resolve(process.argv[2] || '.'), files = ['.claude/hooks/abp.mjs', '.claude/hooks/launch.mjs', '.claude/settings.json', 'abp/policies.json']
const o = { v: 1, about: 'SHA-256 of the files the hook may load; signed by cl-6.abp (abp-pins). A changed file does not load until cl-6.abp signs a new pins.json.', at: new Date().toISOString().slice(0, 16) + 'Z', files: Object.fromEntries(files.map(x => [x, crypto.createHash('sha256').update(fs.readFileSync(path.join(root, x))).digest('hex')])) }
fs.writeFileSync(path.join(root, 'abp/pins.json'), JSON.stringify(o, null, 1) + '\n'); console.log('pins written for', files.length, 'files; now sign them')
