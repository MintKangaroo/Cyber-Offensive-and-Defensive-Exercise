# Live Fire Real-time Behavior

The Attack/Defense UI uses the role-filtered SSE endpoint through a fetch stream
so it can send an Authorization header and explicit `Last-Event-ID`.

Behavior:

- last cursor is stored per Match in `sessionStorage`;
- reconnect uses exponential backoff from 1s to 30s;
- server IDs restore missed events;
- event IDs are deduplicated;
- events are sorted by authoritative server timestamp;
- bursts are batched for 100ms before React state updates;
- the buffer is bounded to 500 events;
- connection and last-received age are visible in the Match header;
- data older than 15s is treated as degraded;
- hidden tabs abort the stream and reconnect when visible;
- score, round and service projections are polled from authoritative APIs and
  are never derived from the event feed;
- participant submissions wait for server confirmation; only form clearing is
  local.

Observer events are filtered on the server. Public score delay is displayed as
round count and last public round. The existing exercise WebSocket/SSE behavior
remains available in the preserved exercise interface.

Malformed single events are isolated rather than terminating the stream. An
HTTP authentication error remains visibly degraded and does not silently grant
operator or competitor views.

The standalone broadcast route deliberately does not use this SSE stream. It
polls the versioned public snapshot at the server-recommended interval (bounded
to 2–30 seconds), anchors its countdown to returned server time and retains the
last confirmed snapshot with a visible `FEED STALE` signal on failure. This
keeps immediate event timing outside the broadcast disclosure boundary.
