#!/usr/bin/env node
// Writes abp/pins.json for an install: the SHA-256 of every file under .claude/** and abp/** that the hook loads or protects (two groups: hook, policy),
// the repository's name, the policy version and a sequence number that only rises. It names no key. cl-6.abp then signs it, by hand:
//   ssh-keygen -Y sign -f <its signing key> -n abp-pins abp/pins.json        (writes abp/pins.json.sig)
// usage: node pins.mjs <install root> [--repo owner/name] [--seq N] [extra file ...]   (extra: the repository's generated ABP, abp/tools.mjs, ...)
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto'; import { execFileSync } from 'node:child_process'
import { normRepo } from './claude/hooks/pinlib.mjs'
const a = process.argv.slice(2), root = path.resolve(a[0] || '.'); let repo = '', seq = 0; const extra = []
for (let i = 1; i < a.length; i++) { if (a[i] === '--repo') repo = a[++i]; else if (a[i] === '--seq') seq = parseInt(a[++i], 10); else extra.push(a[i]) }
if (!repo) { try { repo = execFileSync('git', ['config', '--get', 'remote.origin.url'], { cwd: root, encoding: 'utf8' }).trim() } catch {} }
repo = normRepo(repo); if (!repo) { console.error('no repository name: pass --repo or set remote.origin.url'); process.exit(1) }
if (!seq) { let prev = 0; try { prev = JSON.parse(fs.readFileSync(path.join(root, 'abp/pins.json'))).seq || 0 } catch {} seq = prev + 1 }
const hook = ['.claude/hooks/abp.mjs', '.claude/hooks/launch.mjs', '.claude/hooks/pinlib.mjs', '.claude/settings.json'], policy = ['abp/policies.json', ...extra]
const h = x => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, x))).digest('hex')
let version = ''; try { version = JSON.parse(fs.readFileSync(path.join(root, 'abp/policies.json'))).version } catch {}
const o = { v: 2, about: 'SHA-256 of the files the hook may load; signed by cl-6.abp (abp-pins). A changed file does not load, and does not leave the machine at git commit or git push, until cl-6.abp signs a new pins.json.', repository: repo, version, seq, at: new Date().toISOString().slice(0, 16) + 'Z', groups: { hook, policy }, files: Object.fromEntries([...hook, ...policy].map(x => [x, h(x)])) }
fs.writeFileSync(path.join(root, 'abp/pins.json'), JSON.stringify(o, null, 1) + '\n'); console.log(`pins written: ${repo} policy ${version} seq ${seq}, ${Object.keys(o.files).length} files; now sign them`)
