# cl-6.abp: learnings

- The kit's key fingerprint is the first 16 hex of the SHA-256 of the public key's DER (SPKI), checked against cl-6.conductor's file.
- git verifies ssh signatures only with gpg.ssh.allowedSignersFile; without it "git log --show-signature" says "No signature" although the commit carries a gpgsig. Check with git cat-file commit.
- The kit hook treats a dotted name with no entry as a worker of its base role; here every cl-6 name has its own entry.
