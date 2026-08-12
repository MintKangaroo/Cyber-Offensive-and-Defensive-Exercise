# File Vault

Normal workflow: register, log in, upload a text file, and download that file.
The base image intentionally fails to enforce directory containment on
downloads and returns directory entries reached through that traversal. A
round flag is stored outside the user root through the isolated management
listener. This makes the manual attack path reproducible as
`../../system` discovery followed by reading the discovered file; the patched
image rejects both requests.

See [`expected-patch-behavior.md`](expected-patch-behavior.md). The demo does
not automatically exploit the traversal.
