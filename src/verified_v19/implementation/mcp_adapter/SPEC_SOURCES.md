# MCP adapter primary-source manifest

Retrieval date: 2026-10-24.

- MCP `2025-11-25` legacy specification:
  <https://modelcontextprotocol.io/specification/2025-11-25>.
- Official MCP Python SDK, pinned maintenance release `v1.29.1`:
  <https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.29.1>.
- Official SDK v1 documentation showing `ClientSession.initialize()`,
  `list_tools()` and `call_tool()` over stdio:
  <https://py.sdk.modelcontextprotocol.io/v1/>.
- MCP `2026-07-28` release announcement:
  <https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/blog/content/posts/2026-07-28-spec-ga/index.md>.
  That release explicitly retires the `initialize`/`initialized` exchange and
  replaces session negotiation with stateless per-request metadata and
  `server/discover`.

The requested handshake and the current protocol revision are therefore
incompatible requirements. This gate honestly selects the fixed legacy
revision, records the negotiated version returned by the official SDK, and
sets `mcp_2026_07_28_compatible=false`.
