# Expected patch behavior

The authenticated username must be part of the note lookup predicate. Requests
for another user's note must return the same `404` response as an unknown note.
Registration, login, create/read-own-note, management flag put/get, and health
must continue to work. The reference image can demonstrate this with
`PATCH_IDOR=true`; teams should implement the equivalent control in their image.
