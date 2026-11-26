# Network ABP: one design for security, accountant and telemetry to agree (2026-11-26T16:45Z)

Asked by Dinis (cl-6.maestro's session, about 16:50 UTC, 26 Nov 2026, as cl-6.maestro relays it): "super strict ABP for Network access for all agents here", and capture every network request so breaches can be detected. Written by cl-6.abp. A proposal: nothing here is in force; cl-6.security leads the review.

## 1. What the ABP says (policy and generated ABP)

Every agent's ABP gets a **Network** section, generated from `abp/policies.json` `network`:

- **default: deny.** A host not listed is outside the mandate.
- **common hosts**, for every agent: only what the work cannot do without: `github.com` (git through the session's proxy: the push rules R5 still apply) and `raw.githubusercontent.com` (public reads, GET only).
- **the agent's own hosts**: `roles.<name>.network.hosts`, each with a reason and the rights record for the source (R15 of the PrompTugal policy: a source has its terms quoted on the register before its first read). An agent with no data work has none.
- **who may read the web at all**: the data agents (cl-6.data, the sections, the places, cl-6.researcher, the London agent...) for their own sources only. cl-6.maestro, cl-6.conductor and the other account-level and routing agents: no web reads (Dinis, 26 Nov: that kind of access never from a maestro repository). cl-6.social: none.
- **methods**: GET and HEAD by default; a host that may be sent to (POST and the like) is also in the role's `send_hosts` (R7), which stays empty for everyone today.
- **phase**: `capture` today, then `enforce` (section 4).

## 2. What is captured, in three layers

| Layer | Sees | Misses | Who |
|---|---|---|---|
| **The hook's log** (`~/.abp/log`, protected): for every tool call, the destination hosts it names: WebFetch (the URL's host), Bash (every URL, `git@host:`, and the host arguments of curl, wget, ssh, scp, nc, rsync, git clone, fetch, push, pull, npm, pip, apt, gh), connectors (the MCP server). Event `net`: time, agent, tool, host, method, decision. Paths and query strings are recorded as a keyed hash only (a URL can carry a secret). | anything that runs code (bash -c, python -c, a script it wrote), and WebSearch, which names no host | cl-6.abp (hook v2.2) |
| **The run report** (`reach.hosts`: host, count, first and last time, allowed or not; the schema's `reach` object already carries the attempts) | what the hook logged | the same | the report tool; cl-6.telemetry aggregates |
| **The environment's proxy log** (the sessions' outbound HTTPS goes through the agent proxy, which already writes a line for a refused request) | **every** request of the session, whatever ran it | which agent, when sessions share an environment: it can be matched by session and time | the environment is Dinis's; the log goes read-only to cl-6.telemetry |

**The breach test is the difference.** A host in the proxy log that is not in the hook's log for the same session and time means something got round the hook (a script): a breach, whoever allowed it. A host in the hook's log that is not on the agent's allow-list is a breach (observed or blocked).

## 3. What refuses

- **The hook** (kit v2.2, after this design is agreed; the reviewed head does not move before): a WebFetch or a Bash segment naming a host outside the role's allow-list is denied, kind `network`, rule N1; with the breaker N1 on it blocks, in observe mode it is logged and counted. A segment that names a host it cannot resolve statically (`$X`, a backtick) is denied while N1 is on, as the unknown-cwd rule does.
- **The environment** is the only real boundary: its allowed-hosts list applies to every session in it, not per agent. The design asks Dinis for **environment classes** instead of one Default for all: (a) **no-network** for agents that only draft and route (maestro, conductor, social, security's reviews, decisions, abp, accountant): github.com only; (b) **readers**, a list that is the union of its agents' lists; (c) the data collectors, each section's own. Then the per-agent list is a guardrail inside a per-class boundary. Environment settings are Dinis's alone (an approval prompt every time).

## 4. Phases, so that nobody is blocked by guesswork

1. **Capture (now, no block):** hook v2.2 logs hosts; the run reports carry them; cl-6.telemetry counts per agent and day. Only R7 sends and the existing denials block.
2. **Measure (about 3 days):** per agent, the hosts seen are listed; cl-6.rights confirms the terms of each source; cl-6.security reviews each list; cl-6.abp proposes the allow-lists (a relaxation of "deny": each list is a record cl-6.decisions can sign, or Dinis).
3. **Enforce:** breaker N1 on, per agent as its list is agreed; unknown hosts blocked; the proxy log compared hourly.

## 5. What I need from each

- **cl-6.security (leads):** the threat cases I have not thought of (DNS names, IPs, URL shorteners, redirects; `git` remotes that resolve elsewhere; MCP servers that fetch); whether N1 should block from day one for the no-network class (my view: yes: it has no reason to touch a host).
- **cl-6.accountant:** the cost side: the per-host or per-agent request counts into the ledger; a cap for the data agents' fetches.
- **cl-6.telemetry:** the aggregation (hosts per agent per day) and the comparison of the proxy log with the hook's log; whether it can read the proxy log.
- **Dinis:** the environment classes (3.), the proxy log export, and the order.

## 6. Honest limits

The hook sees the text of tool calls, not packets: a script can still make a request it does not name; only the environment's allow-list and the proxy log catch it, and the proxy log cannot tell two agents of one environment apart except by session and time. A host list is a list of names: it cannot tell what is sent in a GET. Capture is only useful if someone reads it: the hourly review and telemetry's aggregate are that someone.
