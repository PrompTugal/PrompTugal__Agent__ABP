#!/usr/bin/env node
// The CI check (security condition 4), for cl-6.dev to wire as a required status in each repository. Offline, no dependency, Node 18+.
//   ABP_PIN_KEY_SHA256=<the full SHA-256 of cl-6.abp's signing key, from the org's variables: NOT from this repository> node ci-check.mjs <checkout root> [--repo owner/name] [--floor N]
// It checks the commit checked out: abp/pins.json is signed by that key (namespace abp-pins), names this repository, has a sequence number above the floor
// (the last accepted one, kept by CI), and lists, with matching SHA-256, EVERY tracked file under .claude/** and abp/** (except pins.json and its signature).
// Exit 0 passes, 1 fails with the reason.
import fs from 'node:fs'; import path from 'node:path'; import { execFileSync } from 'node:child_process'
import { verifySshsig, sha, normRepo } from './claude/hooks/pinlib.mjs'
const a = process.argv.slice(2), root = path.resolve(a[0] || '.'); let repo = '', floor = 0
for (let i = 1; i < a.length; i++) { if (a[i] === '--repo') repo = a[++i]; else if (a[i] === '--floor') floor = parseInt(a[++i], 10) || 0 }
const fail = why => { console.error('abp ci-check FAIL: ' + why); process.exit(1) }
try {
  if (!process.env.ABP_PIN_KEY_SHA256) fail('ABP_PIN_KEY_SHA256 is not set: the key must come from outside the repository')
  const git = (...x) => execFileSync('git', x, { cwd: root, encoding: 'utf8', stdio: 'pipe' })
  const tracked = git('ls-files', '--', '.claude', 'abp').split('\n').filter(Boolean)
  if (!tracked.length) process.exit(0)   // nothing under .claude or abp: nothing to pin
  const raw = fs.readFileSync(path.join(root, 'abp/pins.json')), sig = fs.readFileSync(path.join(root, 'abp/pins.json.sig'), 'utf8')
  verifySshsig(sig, raw, 'abp-pins'); const pins = JSON.parse(raw)
  if (!repo) repo = git('config', '--get', 'remote.origin.url').trim()
  if (pins.repository !== normRepo(repo)) fail(`the pins are for ${pins.repository}, not ${normRepo(repo)}`)
  if (!Number.isInteger(pins.seq) || pins.seq <= floor) fail(`sequence ${pins.seq} is not above the last accepted ${floor}`)
  const bad = tracked.filter(f => f !== 'abp/pins.json' && f !== 'abp/pins.json.sig').filter(f => { try { return !pins.files?.[f] || sha(fs.readFileSync(path.join(root, f))) !== pins.files[f] } catch { return true } })
  if (bad.length) fail('not covered by the signed pins, or changed: ' + bad.slice(0, 8).join(', ') + (bad.length > 8 ? ` and ${bad.length - 8} more` : ''))
  console.log(`abp ci-check OK: ${normRepo(repo)} policy ${pins.version} seq ${pins.seq}, ${tracked.length - 2} files covered`)
} catch (e) { fail(String(e.message).slice(0, 160)) }
