"""Deterministic, credential-free XiaoZhi WebSocket protocol simulator.

Reference: 78/xiaozhi-esp32@92d400d6374bbe750e0a0188fa969fc4042820c2
No ASR, LLM, TTS, MCP server, OTA, user data, or physical hardware is contacted.
"""
import asyncio
from http import HTTPStatus
import json
import os
import socket
import struct

from websockets.asyncio.server import serve

MAX_MESSAGE = 65536
MAX_AUDIO = 4096
FIXTURE_TOKEN = "Bearer synthetic-fixture-only"
FIXTURE_MAC = "02:00:00:00:00:01"
FIXTURE_CLIENT = "00000000-0000-4000-8000-000000000001"
UPSTREAM_SHA = "92d400d6374bbe750e0a0188fa969fc4042820c2"


class ProtocolError(ValueError):
    pass


def credential_guard():
    """Refuse local test execution in an environment with real-looking secrets."""
    for key, value in os.environ.items():
        if ("TOKEN" in key.upper() or "API_KEY" in key.upper() or "SECRET" in key.upper()) and value and value != "synthetic-fixture-only":
            raise RuntimeError("environment credential present: refusing simulator run")


def loopback_guard(host):
    if host not in ("127.0.0.1", "::1"):
        raise RuntimeError("simulator only accepts numeric loopback addresses")
    if not socket.getaddrinfo(host, None):
        raise RuntimeError("loopback unavailable")


def encode_audio(version, payload, *, timestamp=1):
    if len(payload) > MAX_AUDIO:
        raise ProtocolError("oversized audio")
    if version == 1:
        return bytes(payload)
    if version == 2:
        return struct.pack("!HHII", 2, 0, timestamp, len(payload)) + payload
    if version == 3:
        return struct.pack("!BBH", 0, 0, len(payload)) + payload
    raise ProtocolError("unsupported audio version")


def decode_audio(version, frame):
    if len(frame) > MAX_AUDIO + 12:
        raise ProtocolError("oversized frame")
    if version == 1:
        payload = frame
    elif version == 2:
        if len(frame) < 12:
            raise ProtocolError("truncated v2 header")
        protocol, kind, _timestamp, length = struct.unpack("!HHII", frame[:12])
        if protocol != 2 or kind != 0 or length != len(frame) - 12:
            raise ProtocolError("invalid v2 frame")
        payload = frame[12:]
    elif version == 3:
        if len(frame) < 4:
            raise ProtocolError("truncated v3 header")
        kind, reserved, length = struct.unpack("!BBH", frame[:4])
        if kind != 0 or reserved != 0 or length != len(frame) - 4:
            raise ProtocolError("invalid v3 frame")
        payload = frame[4:]
    else:
        raise ProtocolError("unsupported audio version")
    if len(payload) > MAX_AUDIO:
        raise ProtocolError("oversized audio")
    return payload


def valid_server_hello(data):
    """Upstream permits optional session_id and audio_params."""
    if not isinstance(data, dict) or data.get("type") != "hello" or data.get("transport") != "websocket":
        return False
    if "session_id" in data and not isinstance(data["session_id"], str):
        return False
    if "audio_params" in data and not isinstance(data["audio_params"], dict):
        return False
    return True


def mcp_request(version, method="tools/list", request_id=1, cursor=None):
    if version not in ("2024-11-05", "2026-07-28"):
        raise ProtocolError("unsupported MCP version")
    if not isinstance(request_id, (str, int)) or isinstance(request_id, bool) or (isinstance(request_id, int) and abs(request_id) > 2**53 - 1):
        raise ProtocolError("unsafe MCP request id")
    if method == "initialize":
        params = {"protocolVersion": "2024-11-05", "capabilities": {},
                  "clientInfo": {"name": "synthetic-simulator", "version": "0"}}
    else:
        params = {} if method != "tools/list" else {"withUserTools": False}
        if cursor is not None:
            params["cursor"] = cursor
    if version == "2026-07-28":
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "synthetic-simulator", "version": "0"},
        }
    return {"type": "mcp", "payload": {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}}


def valid_mcp_response(payload, outstanding, method="tools/list"):
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return False
    rid = payload.get("id")
    if (isinstance(rid, bool) or not isinstance(rid, (str, int))
            or (isinstance(rid, int) and abs(rid) > 2**53 - 1)
            or rid not in outstanding):
        return False
    result = payload.get("result")
    if not isinstance(result, dict):
        return False
    if method == "initialize":
        return result.get("protocolVersion") == "2024-11-05" and isinstance(result.get("capabilities"), dict)
    if method == "server/discover":
        return (result.get("resultType") == "complete"
                and isinstance(result.get("supportedVersions"), list)
                and "2026-07-28" in result["supportedVersions"])
    if method != "tools/list" or not isinstance(result.get("tools"), list):
        return False
    if len(result["tools"]) > 20:
        return False
    if "nextCursor" in result and not isinstance(result["nextCursor"], str):
        return False
    return all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in result["tools"])


class SimulatorGateway:
    """Synthetic, read-only gateway. Never forwards tools to any MCP endpoint."""

    def __init__(self):
        self.counter = 0
        self.sessions = set()
        self.mcp_accepted = 0
        self.mcp_dropped = 0
        self.audio_frames = 0
        self.denied_calls = 0
        self.revoke = False

    def authorize(self, connection, request):
        h = request.headers
        if (self.revoke or h.get("Authorization") != FIXTURE_TOKEN
                or h.get("Device-Id") != FIXTURE_MAC
                or h.get("Client-Id") != FIXTURE_CLIENT
                or h.get("Protocol-Version") not in ("1", "2", "3")):
            return connection.respond(HTTPStatus.UNAUTHORIZED, "simulator fixture rejected")
        return None

    async def handler(self, ws):
        task = None
        pending_mcp = {}
        mcp_version = None
        mcp_seq = 0
        self.counter += 1
        session = f"synthetic-{self.counter}"
        self.sessions.add(session)
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=0.8)
            if not isinstance(raw, str) or len(raw) > MAX_MESSAGE:
                await ws.close(code=1008, reason="invalid hello")
                return
            try:
                hello = json.loads(raw)
            except (ValueError, TypeError):
                await ws.close(code=1008, reason="invalid json")
                return
            if (not isinstance(hello, dict) or hello.get("type") != "hello"
                    or hello.get("transport") != "websocket"
                    or type(hello.get("version")) is not int
                    or hello["version"] not in (1, 2, 3)
                    or not isinstance(hello.get("audio_params"), dict)
                    or hello["audio_params"].get("format") != "opus"
                    or hello["audio_params"].get("sample_rate") != 16000
                    or hello["audio_params"].get("channels") != 1):
                await ws.close(code=1008, reason="invalid hello")
                return
            version = hello["version"]
            await ws.send(json.dumps({"type": "hello", "transport": "websocket", "session_id": session}))
            features = hello.get("features") or {}
            if isinstance(features, dict) and features.get("mcp") is True:
                mcp_version = "2026-07-28" if features.get("mcp_20260728") is True else "2024-11-05"
                initial = "server/discover" if mcp_version == "2026-07-28" else "initialize"
                pending_mcp[1] = initial
                mcp_seq = 1
                await ws.send(json.dumps(mcp_request(mcp_version, initial, request_id=1)))
            active = False
            async for raw in ws:
                if isinstance(raw, bytes):
                    try:
                        decode_audio(version, raw)
                        self.audio_frames += 1
                    except ProtocolError:
                        await ws.close(code=1008, reason="invalid audio")
                        break
                    continue
                if len(raw) > MAX_MESSAGE:
                    await ws.close(code=1009, reason="oversized json")
                    break
                try:
                    message = json.loads(raw)
                except (ValueError, TypeError):
                    await ws.close(code=1008, reason="invalid json")
                    break
                if not isinstance(message, dict):
                    await ws.close(code=1008, reason="invalid message")
                    break
                kind = message.get("type")
                if kind == "listen":
                    if message.get("state") == "start":
                        active = True
                    elif message.get("state") == "stop" and active:
                        active = False
                        await ws.send(json.dumps({"type": "stt", "text": "synthetic build status"}))
                        await ws.send(json.dumps({"type": "tts", "state": "start"}))
                        await ws.send(json.dumps({"type": "tts", "state": "sentence_start", "text": "synthetic ok"}))
                        task = asyncio.create_task(self.stream_audio(ws, session, version))
                    else:
                        await ws.close(code=1008, reason="invalid listen")
                        break
                elif kind == "abort":
                    if task:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    await ws.send(json.dumps({"type": "tts", "state": "stop"}))
                elif kind == "mcp":
                    payload = message.get("payload")
                    rid = payload.get("id") if isinstance(payload, dict) else None
                    # Malformed/unsolicited replies have no authority to trigger tool use.
                    if (not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0"
                            or not isinstance(rid, (str, int)) or isinstance(rid, bool)
                            or (isinstance(rid, int) and abs(rid) > 2**53 - 1)
                            or rid not in pending_mcp):
                        self.mcp_dropped += 1
                        continue
                    method = pending_mcp[rid]
                    # Only -32601 on modern discovery permits a fallback to legacy.
                    if (method == "server/discover" and isinstance(payload.get("error"), dict) and payload["error"].get("code") == -32601):
                        del pending_mcp[rid]
                        self.mcp_accepted += 1
                        mcp_version = "2024-11-05"
                        mcp_seq += 1
                        pending_mcp[mcp_seq] = "initialize"
                        await ws.send(json.dumps(mcp_request(mcp_version, "initialize", request_id=mcp_seq)))
                        continue
                    if not valid_mcp_response(payload, {rid}, method=method):
                        self.mcp_dropped += 1
                        continue
                    del pending_mcp[rid]
                    self.mcp_accepted += 1
                    if method in ("server/discover", "initialize"):
                        mcp_seq += 1
                        pending_mcp[mcp_seq] = "tools/list"
                        await ws.send(json.dumps(mcp_request(mcp_version, "tools/list", request_id=mcp_seq)))
                    elif method == "tools/list":
                        # Catalog is never executed, and descriptions are discarded.
                        cursor = payload["result"].get("nextCursor")
                        if cursor:
                            mcp_seq += 1
                            pending_mcp[mcp_seq] = "tools/list"
                            await ws.send(json.dumps(mcp_request(mcp_version, "tools/list", request_id=mcp_seq, cursor=cursor)))
                else:
                    self.denied_calls += 1
                    await ws.close(code=1008, reason="unrecognized message")
                    break
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            self.sessions.discard(session)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def stream_audio(self, ws, session, version):
        try:
            for _ in range(8):
                if session not in self.sessions:
                    return
                await ws.send(encode_audio(version, b"synthetic-audio"))
                await asyncio.sleep(0.025)
            if session in self.sessions:
                await ws.send(json.dumps({"type": "tts", "state": "stop"}))
        except asyncio.CancelledError:
            raise

    async def start(self):
        loopback_guard("127.0.0.1")
        server = await serve(self.handler, "127.0.0.1", 0,
                             process_request=self.authorize, max_size=MAX_MESSAGE)
        port = server.sockets[0].getsockname()[1]
        return server, f"ws://127.0.0.1:{port}"