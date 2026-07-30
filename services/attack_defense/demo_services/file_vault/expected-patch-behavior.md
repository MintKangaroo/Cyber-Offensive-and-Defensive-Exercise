# Expected patch behavior

Resolve the requested path and verify that it remains under the authenticated
user's root before reading. Invalid and unknown paths both return `404`.
Registration, login, safe upload/download, management flag put/get, and health
must continue to work. The reference behavior is available with
`PATCH_TRAVERSAL=true`.
