// ABP kit v2.1 pin library (Apache-2.0 code, adapted from the ABP starter kit): the one place that checks cl-6.abp's SSH signature (abp-pins).
// Used by the launcher (at load) and by the hook (at git commit and git push, to let a signed install through). Pinned like the other kit files.
import crypto from 'node:crypto'
export const PIN_KEY_SHA256 = 'eb5b09f0fa1e6e67ae643c623986869f12d6dd2526ffab53b1ca35bacd299326'   // the FULL SHA-256 of the SPKI of cl-6.abp's signing key (site/keys/cl-6.abp.json): the only key whose pins load
export const keyHash = () => process.env.ABP_PIN_KEY_SHA256 || PIN_KEY_SHA256   // v2.1 (security condition 1): a key set by the environment (IaC) wins over the constant in this file, which sits in the repository being checked
export const normRepo = u => String(u || '').toLowerCase().replace(/^[a-z+]+:\/\/([^@/]*@)?|^[^@/\s]+@/g, '').replace(/\.git\/?$|\/$/g, '').replace(/^([^/:]+):(?!\d+\/)/, '$1/')
export const sha = b => crypto.createHash('sha256').update(b).digest('hex')
const rd = (b, o) => { const n = b.readUInt32BE(o); return [b.subarray(o + 4, o + 4 + n), o + 4 + n] }
export function verifySshsig(armored, message, namespace) {
  const body = Buffer.from(armored.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64')
  if (body.subarray(0, 6).toString() !== 'SSHSIG' || body.readUInt32BE(6) !== 1) throw new Error('not an sshsig version 1'); let o = 10, pk, ns, rs, ha, sg   // v2 (F6)
  ;[pk, o] = rd(body, o); [ns, o] = rd(body, o); [rs, o] = rd(body, o); [ha, o] = rd(body, o); [sg, o] = rd(body, o)
  if (ns.toString() !== namespace || rs.length !== 0) throw new Error('wrong namespace or a reserved field that is not empty')
  let p = 0, t, curve, Q; [t, p] = rd(pk, p); [curve, p] = rd(pk, p); [Q, p] = rd(pk, p)
  if (t.toString() !== 'ecdsa-sha2-nistp256' || Q.length !== 65) throw new Error('not P-256')
  const spki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Q])
  if (sha(spki) !== keyHash()) throw new Error('signed by another key')
  const h = ha.toString() === 'sha512' ? 'sha512' : ha.toString() === 'sha256' ? 'sha256' : null; if (!h) throw new Error('hash')
  const signed = Buffer.concat([Buffer.from('SSHSIG'), ...[ns, rs, ha, crypto.createHash(h).update(message).digest()].flatMap(x => { const l = Buffer.alloc(4); l.writeUInt32BE(x.length); return [l, x] })])
  let q = 0, ty, sd, r, s; [ty, q] = rd(sg, q); [sd, q] = rd(sg, q); let z = 0;[r, z] = rd(sd, z); [s, z] = rd(sd, z)
  const fix = x => { x = x[0] === 0 ? x.subarray(1) : x; return Buffer.concat([Buffer.alloc(32 - x.length), x]) }
  if (!crypto.verify('sha256', signed, { key: crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }), dsaEncoding: 'ieee-p1363' }, Buffer.concat([fix(r), fix(s)]))) throw new Error('bad signature')
}
