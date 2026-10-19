# Rex Server Protocol - Reverse Engineering Notes

## Transport
- HTTPS with WebSocket upgrade
- Control channel: `/api/control` with subprotocol `rex.control.v1`
- Data channel: `/api/data` (terminal PTY I/O, connected via ticket from `data.connect`)

## Message Framing (WebSocket text frames)

Messages have a `type` field:
- `"welcome"` - server sends on connection, with `"protocol": "rex.control.v1"`
- `"request"` - client sends, with `"id"`, `"method"`, and optional args
- `"response"` - server sends, with `"id"` matching request, `"seq"` for event ordering
- `"event"` - server sends, with event type and payload

## Client Connection Flow

1. Client connects to `wss://HOST/api/control` with `Sec-WebSocket-Protocol: rex.control.v1`
2. Server sends welcome: `{"type":"welcome","protocol":"rex.control.v1"}`
3. Client sends `session.bootstrap` with `{"event_scope":"all"}`
4. Server responds with full state (client_id, server_status, sessions, views)
5. Server streams events as state changes
6. For terminal I/O, client calls `data.connect` → gets ticket → opens `/api/data` with ticket

## Key Methods (71 total)
See rex-api-schema.json for full schemas.

### Essential for MVP
- server.status, server.version, server.whoami
- session.bootstrap, session.list, session.create, session.destroy
- session.attach, session.attach_all, session.view
- session.new_window, session.new_split
- block.method (dispatches to terminal methods)
- block.close
- data.connect
- block_creator.list
- hosts.list, client.list

## ID Format
- Sessions: `session:UUID-V7`
- Windows: `window:UUID-V7`  
- Blocks: `block:UUID-V7`
- Layers: `layer:UUID-V7`
- Clients: `client:UUID-V7`

## Terminal Block
- Creator: `com.superlogical.terminal`
- Flavor: `com.superlogical.terminal.shell`
- Methods: resize, write, format, clear, reset, title, pwd, process, size, etc.
- Data subprotocol: `rex.data.terminal.v1`
