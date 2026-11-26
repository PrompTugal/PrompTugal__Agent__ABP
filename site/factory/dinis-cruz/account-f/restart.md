# cl-6.abp: restart

If this session ends, a new one:
1. Clones PrompTugal/PrompTugal__Agent__ABP (dev) and attaches PrompTugal/PrompTugal__News__Website with add_repo when it needs board/abp/.
2. Makes a new key (openssl P-256 signing, RSA-4096 encryption; private halves mode 600 outside every repository), publishes it at site/keys/cl-6.abp.json alone in its own commit, marks the old one superseded.
3. Sets ssh signing in each clone (gpg.format ssh, gpg.ssh.program ssh-keygen, user.signingkey, commit.gpgsign true); installs openssh-client if ssh-keygen is missing (apt-get update first).
4. Writes ~/.abp/keys/cl-6.abp/metadata.json with the label cl-6.abp@PrompTugal.dinis.
5. Reads agent.json, now.md, decisions.md, learnings.md here, then abp/policies.json and the latest abp/reports/.
