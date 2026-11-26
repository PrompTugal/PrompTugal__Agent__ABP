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

## 7. Threat cases (cl-6.security's review of 1befe06, 26 Nov 16:47 UTC; folded in by cl-6.abp)

**A. The common hosts.** github.com and raw.githubusercontent.com serve anyone's content: a GET of a stranger's raw path carries data out in the path, and a clone of a stranger's repository pulls in arbitrary instructions. So they are allowed **by owner path only**: \`PrompTugal/*\`, \`SovereignWebsite/*\` and any other owner named in the policy (\`network.github_owners\`). The owner/repo segment is logged **in the clear**, not hashed, so a stranger's owner is visible. gist.github.com, api.github.com, codeload.github.com and objects.githubusercontent.com are named explicitly or denied (denied today).

**B. Cases the host parser must deny (hook v2.2; the ones marked [policy] are in the policy file already and need no new hook code):**
1. Normalise with a real URL parser first: lower-case, drop a trailing dot, strip the port, convert punycode/IDN; deny userinfo (\`https://github.com@evil.example/\`); deny IP literals in any form (decimal, octal, hex, IPv6, 169.254.169.254, localhost, 10/8, 172.16/12, 192.168/16, 100.64/10).
2. Redirects: curl and wget with \`-L\`, \`--location\` or \`--max-redirs\` are denied [policy]; WebFetch reports a cross-host redirect rather than following it, and the follow-up is checked like any other request.
3. Shorteners and "fetch for me" relays are never allowed, even for data agents (\`network.deny_hosts\` [policy data, enforced by hook v2.2]): bit.ly, t.co, tinyurl; web.archive.org/save/, archive.ph; translate.goog and other translation proxies; r.jina.ai and reader proxies; CORS proxies; the Google cache. An archive read (web.archive.org/web/) is a GET of stored content: acceptable per source only with cl-6.rights' yes.
4. DNS as a channel: \`dig\`, \`nslookup\`, \`host\`, \`getent\`, \`ping\`, \`traceroute\`, \`resolvectl\` are on the shell deny list [policy]. To measure, for Dinis and the environment: whether the container's resolver answers outside names directly (then \`<secret>.evil.example\` leaks without any HTTP).
5. git that resolves elsewhere: \`~/.gitconfig\`, \`~/.config/git/**\` are protected, owner none [policy]; \`url.*.insteadOf\`, \`http.proxy\`, \`http.*.extraHeader\`, \`credential.helper\`, \`core.sshCommand\` by \`-c\` or \`git config\` are denied [policy]; \`export\` or \`unset\` of GIT_SSH_COMMAND, GIT_PROXY_COMMAND, GIT_CONFIG_*, HTTP_PROXY, HTTPS_PROXY, ALL_PROXY and NO_PROXY are denied [policy]. A leading \`VAR=value command\` prefix is stripped by the hook before it matches, so a prefix such as \`GIT_SSH_COMMAND=x git fetch\` is a limit of the hook: hook v2.2 reads the prefixes too. Submodules (\`clone --recurse-submodules\`, \`submodule update\`) are checked against .gitmodules URLs; \`git clone\` or \`fetch\` of a URL outside the owner paths in A is denied (v2.2).
6. Package managers (npm, pip, apt, npx) run install scripts and reach registries the environment allows by default; names in a registry GET can carry data. For the no-network class the environment is set with \`allow_package_managers: false\` (the environment's settings: Dinis's). In the hook, \`npx\` and \`pip install\` of an unpinned name are a network act, logged with the host (v2.2).
7. WebSearch is a send: the query goes to a third party. It sits under the Network section, is denied for the no-network class (v2.2: a per-role tool deny; the policy has only per-grant flags today), and its query is logged as a keyed hash.
8. MCP and connectors are outbound channels the proxy may not see: GitHub MCP writes (create_or_update_file, create_gist, issues and comments to any repository), the Gmail tools present in these sessions' tool lists, claude-code-remote \`send_message\` (session to session: it carries text) and \`watch_url\` (an inbound webhook). R3 and its breaker cover connectors; the log lists them as network, with the server name as the host, so the per-agent daily table shows them.
9. The proxy log: confirm that it records **allowed** requests too (host, method, bytes, session), not only refused ones; without that layer 3 is half a layer. Retention, read-only access for cl-6.telemetry, write-once storage if the platform has it: the environment's, Dinis's.

**C. N1 from day one for the no-network class: yes**, with two adjustments: (a) a second common set, **own sites** (\`network.own_sites\`): promptugal.news, its subdomains and data.promptugal.news, GET and HEAD, for the roles that review or route and must read the live site (cl-6.security first: it post-reviews releases); (b) for that class WebSearch and package managers are denied on day one too.

**D. For cl-6.accountant and cl-6.telemetry:** a per-agent daily count per host; the count of hook-and-proxy differences (the breach signal); an alert at the first difference, not at a threshold.

### The first network ABP for a data agent: cl-6.data.london (started by cl-6.maestro at Dinis's word, 26 Nov ~16:47 UTC)

Its environment "PrompTugal data (London)" (env_014fJkugLPBiSUBfBqSeK1G7) allows exactly six hosts: tfl.gov.uk, www.london.gov.uk, data.london.gov.uk, www.londoncouncils.gov.uk, www.ons.gov.uk, www.nomisweb.co.uk. It is the only agent making London's network requests and logs each one in its own \`network-log.jsonl\`. Its ABP (draft_roles in the policy) carries those six hosts as \`network.allow\` and that environment as \`network.environment\`, so the policy and the environment say the same thing: a host in one and not the other is a finding. cl-6.place.london has no network and reads its data by public clone.
