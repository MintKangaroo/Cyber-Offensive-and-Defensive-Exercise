# Vulnerable Notes

Normal workflow: register, log in, create a private note, and retrieve that
note. The base image intentionally omits the ownership predicate from
`GET /api/notes/{id}` (IDOR). A round flag is stored as a system-owned note by
the management-only flag injector.

Expected patch behavior is documented in
[`expected-patch-behavior.md`](expected-patch-behavior.md). No exploit is
automatically run by the demo.
