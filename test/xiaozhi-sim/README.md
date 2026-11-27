# XiaoZhi CI-only protocol simulator (MCTL #1409)

Reference pinned upstream: [`78/xiaozhi-esp32@92d400d6374bbe750e0a0188fa969fc4042820c2`](https://github.com/78/xiaozhi-esp32/tree/92d400d6374bbe750e0a0188fa969fc4042820c2). Software-only. **Not tested on K151. Not a PA client.**

Run: `python -m pip install -r test/xiaozhi-sim/requirements.txt && python test/xiaozhi-sim/run.py` from the repository root. No cloud, external network, credentials or real identities are used by the tests. The only TCP endpoint is `127.0.0.1` with an ephemeral port.

Covers WebSocket/Opus-envelope compatibility for protocol versions 1/2/3 (codec **stub**, not real Opus), synthetic listen/STT/TTS/interrupt, authorization rejection, reconnect/session rotation, invalid JSON and truncated binary, and a synthetic device-as-MCP-server control plane validation for old/new versions, modern discovery, legacy fallback and pagination. Real-world speech, crypto pairing, vendor cloud independence, latency/cost and firmware-side safety are **not** established by these tests. The upstream server hello permits absent `session_id` and `audio_params`; the simulator always supplies a session id as local policy. The upstream client's hello timeout is 10 s; our accelerated local timeout is not a hardware performance measure.

The deterministic fixture owner is synthetic, the token is the literal `synthetic-fixture-only`, and the audio bytes are not encoded sound. No vendor OTA, PA scopes, user-data disclosure, physical motor control or downstream MCP tool calls occur. Tool results are never forwarded; a single fabricated build-status exchange is generated locally.

Pass means `protocol_compatible_sim` **only**. A green test never implies real K151, live ASR/LLM/TTS, safe device firmware or PA authorization. Any real device, credentials, public listener, release, merge or PA integration requires separate owner gate and threat-model review.