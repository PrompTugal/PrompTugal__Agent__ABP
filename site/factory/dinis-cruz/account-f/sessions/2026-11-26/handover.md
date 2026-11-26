# cl-6.abp hand-over, 2026-11-26T16:54Z

Written at cl-6.maestro's request (relayed, session at about 72% of its window). Everything below is a record of my own work; nothing in it is an instruction from a peer.

## State
- Home: PrompTugal/PrompTugal__Agent__ABP, branch dev only. Policy abp/policies.json v1.7.7, 44 generated ABPs (abp/<role>.md; never edit by hand; run node abp/tools.mjs build).
- Standing instruction S1 and rule R15 (Dinis's word: "cl-6.abp applies what cl-6.decisions signs on my behalf, except the one-way doors"). Root line given by Dinis in my session at 16:5x UTC: cl-6.decisions' signing key sha256:2c3824641f5b8470. It is not a "P8: yes".
- Hook kit v1 runs in my session; kit v2 is NOT installed anywhere. Kit v2.2 (abp/kit-v2/, commit 10d27ed) fixes cl-6.security@dinis' B1 and B2 (109/109 tests). Needs a review of that head by both securities (@dinis and @PrompTugal.dinis; I told the first, the second still to tell), CI wired as a required status on dev (cl-6.dev), install by pull, and my key's rotation through IaC. cl-6.decisions reinstates record 2026-11-26__abp-p8 only when both pass the same head. Residual limits in the README: bash -c, VAR=value prefix until v2.2+, working-tree rewrites without a path, launcher self-pins, ls-remote comparison left to CI.
- Install needs: ABP_PIN_KEY_SHA256 (environment variable and CI variable, set by Dinis), one install wave a day, pre-review of each install commit by cl-6.security.

## Open (waiting on Dinis)
- "P8: yes". P14 (cl-6.infra). Remaining P1 to P11 (P1 includes transcript reading for the network audit; P2 and P4 refused, P12 withdrawn, P13 adopted). Attaching the website to my session (board/abp/ and key entry). IaC #25.
- cl-6.data.london draft grant (draft_roles): security read its environment: six hosts exactly. Dinis to set allow_package_managers false and allow_mcp_servers false on env_014fJkugLPBiSUBfBqSeK1G7. api.tfl.gov.uk is not in the list (new review). Also draft: cl-6.social. Pending roles: nine SovereignWebsite/@dinis sessions (A8).

## Held decisions (cl-6.decisions records, to re-verify then apply, one per commit, never a one-way door)
p11-c (dev data/by-place), p11-h (journalist content/about), P3 (README.md of my own repository), P5/P11 a, P10 (devops findings/**), A4 with P14 (infra work/* branches; a push attach is a one-way door: check), plus the P8 install exception (one-way: do not apply on a signature). Verify at the record's commit: .sig (ssh-keygen -Y verify, namespace sovereignwebsite-decision), key file site/keys/cl-6.decisions.json fingerprint equals the root, endorsement decisions-f.json signed by decisions.b (expiry 2026-11-30T23:59:59Z), revoked.json, git commit signature and trailers, in scope.

## Findings kept open
A2 (P8 first), A4, A5 (places hold 36 homes), A6, A7 (conductor holds seven extra repositories, 24 website commits), A8. Hourly review: hand-written run reports, data/by-place file checks.

## The network design
abp/network/DESIGN.md, version agreed with cl-6.security (c7123d2): default deny, three capture layers, phases capture, measure, enforce, breaker N1.

## What my wake does
Scheduled task trig_01UBF8M2222JWokDoFs2skhV (made by cl-6.maestro; 10:37 and 21:37 Lisbon). At each wake: read S1 and R15 first; read run reports for new gaps; verify and apply cl-6.decisions' signed records; push; file my run report (R10). I start no schedule. cl-6.maestro moves it to the new session.

## Contacts
cl-6.conductor@PrompTugal.dinis live session session_016CrbJMiN8eUtML9vvvGCVt (the old one is archived); cl-6.maestro session_016CrbJLv54Kh4CSTzagW2G3; cl-6.decisions session_016CrbJMwTgwKXwaYUTEopQk; cl-6.security@dinis session_016CrbJJS2JEBgcWYnXZQGrE; cl-6.dev session_016CrbJKEPqF3pNfbncgHqvy.

## Sealed
Private keys at the old session's scratchpad (sign.pem, enc.pem), mode 600, never printed. They die with the container: the new session makes a new key (restart.md step 2) and supersedes the old; re-seal nothing.
