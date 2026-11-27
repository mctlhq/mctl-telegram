import asyncio
import json
import struct
import unittest

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from harness import (
    FIXTURE_TOKEN, FIXTURE_MAC, FIXTURE_CLIENT, MAX_MESSAGE,
    ProtocolError, SimulatorGateway, credential_guard, loopback_guard,
    decode_audio, encode_audio, mcp_request, valid_mcp_response, valid_server_hello,
)

HEADERS = {"Authorization": FIXTURE_TOKEN, "Device-Id": FIXTURE_MAC,
           "Client-Id": FIXTURE_CLIENT, "Protocol-Version": "3"}
HELLO = {"type": "hello", "version": 3, "transport": "websocket",
         "audio_params": {"format": "opus", "sample_rate": 16000,
                          "channels": 1, "frame_duration": 60}}


class ProtocolUnitTests(unittest.TestCase):
    def test_server_hello_optional_fields(self):
        self.assertTrue(valid_server_hello({"type": "hello", "transport": "websocket"}))
        self.assertTrue(valid_server_hello({"type": "hello", "transport": "websocket", "session_id": "x"}))
        self.assertTrue(valid_server_hello({"type": "hello", "transport": "websocket", "audio_params": {}}))
        self.assertFalse(valid_server_hello({"type": "hello", "transport": "mqtt"}))
        self.assertFalse(valid_server_hello({"type": "hello", "transport": "websocket", "session_id": 3}))

    def test_binary_roundtrip_v1_v2_v3(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                self.assertEqual(decode_audio(version, encode_audio(version, b"synthetic-audio")), b"synthetic-audio")

    def test_binary_truncation_and_forged_length(self):
        for version, invalid in [(2, b"\x02"), (3, b"\x00"),
                                 (2, struct.pack("!HHII", 2, 0, 1, 1000) + b"small"),
                                 (3, struct.pack("!BBH", 0, 0, 1000) + b"small")]:
            with self.subTest(version=version):
                with self.assertRaises(ProtocolError):
                    decode_audio(version, invalid)
        with self.assertRaises(ProtocolError):
            encode_audio(3, b"x" * 5000)

    def test_modern_and_legacy_mcp_messages(self):
        old = mcp_request("2024-11-05", "initialize")
        modern = mcp_request("2026-07-28", "server/discover")
        self.assertNotIn("_meta", old["payload"]["params"])
        self.assertEqual(old["payload"]["params"]["protocolVersion"], "2024-11-05")
        self.assertEqual(modern["payload"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        self.assertEqual(mcp_request("2026-07-28", cursor="cursor-2")["payload"]["params"]["cursor"], "cursor-2")
        with self.assertRaises(ProtocolError):
            mcp_request("2099-01-01")

    def test_mcp_ids_payload_and_fail_closed(self):
        good = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "self.audio_speaker.set_volume"}]}}
        self.assertTrue(valid_mcp_response(good, {1}))
        self.assertTrue(valid_mcp_response(dict(good, id="request-1"), {"request-1"}))
        for invalid in [dict(good, id=True), dict(good, id=123),
                        dict(good, id=1.5), dict(good, result={"tools": None}),
                        dict(good, jsonrpc="1.0")]:
            self.assertFalse(valid_mcp_response(invalid, {1}))

    def test_loopback_guard(self):
        loopback_guard("127.0.0.1")
        with self.assertRaises(RuntimeError):
            loopback_guard("0.0.0.0")
        with self.assertRaises(RuntimeError):
            loopback_guard("example.com")


class LiveLoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.gateway = SimulatorGateway()
        self.server, self.url = await self.gateway.start()

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def open_device(self, hello=HELLO, headers=None):
        ws = await connect(self.url, additional_headers=HEADERS if headers is None else headers)
        await ws.send(json.dumps(hello))
        reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
        return ws, reply

    async def test_invalid_token_denied_before_hello(self):
        with self.assertRaises(InvalidStatus):
            async with connect(self.url, additional_headers={**HEADERS, "Authorization": "Bearer wrong"}):
                pass
        self.gateway.revoke = True
        with self.assertRaises(InvalidStatus):
            async with connect(self.url, additional_headers=HEADERS):
                pass

    async def test_correct_hello_and_session_rotation(self):
        async with await connect(self.url, additional_headers=HEADERS) as ws:
            await ws.send(json.dumps(HELLO))
            first = json.loads(await ws.recv())
            self.assertTrue(valid_server_hello(first))
        async with await connect(self.url, additional_headers=HEADERS) as ws:
            await ws.send(json.dumps(HELLO))
            second = json.loads(await ws.recv())
            self.assertNotEqual(first["session_id"], second["session_id"])

    async def test_invalid_hello_is_rejected(self):
        ws = await connect(self.url, additional_headers=HEADERS)
        try:
            await ws.send(json.dumps({**HELLO, "version": 99}))
            with self.assertRaises(ConnectionClosed):
                await ws.recv()
        finally:
            await ws.close()

    async def test_stream_to_synthetic_read_only_stub(self):
        ws, hello = await self.open_device()
        try:
            self.assertTrue(valid_server_hello(hello))
            await ws.send(json.dumps({"type": "listen", "state": "start"}))
            await ws.send(encode_audio(3, b"synthetic-opaque-frame"))
            await ws.send(json.dumps({"type": "listen", "state": "stop"}))
            kinds = []
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=2)
                if isinstance(msg, bytes):
                    self.assertEqual(decode_audio(3, msg), b"synthetic-audio")
                    kinds.append("audio")
                else:
                    obj = json.loads(msg)
                    kinds.append(obj["type"] + ":" + obj.get("state", ""))
                    if obj == {"type": "tts", "state": "stop"}:
                        break
            self.assertEqual(kinds[:3], ["stt:", "tts:start", "tts:sentence_start"])
            self.assertIn("audio", kinds)
            self.assertEqual(self.gateway.audio_frames, 1)
        finally:
            await ws.close()

    async def test_interrupt_stops_future_audio(self):
        ws, _ = await self.open_device()
        try:
            await ws.send(json.dumps({"type": "listen", "state": "start"}))
            await ws.send(json.dumps({"type": "listen", "state": "stop"}))
            while True:
                item = await asyncio.wait_for(ws.recv(), timeout=1)
                if isinstance(item, bytes):
                    break
            await ws.send(json.dumps({"type": "abort", "reason": "wake_word_detected"}))
            while True:
                item = await asyncio.wait_for(ws.recv(), timeout=1)
                if not isinstance(item, bytes) and json.loads(item) == {"type": "tts", "state": "stop"}:
                    break
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(ws.recv(), timeout=0.1)
        finally:
            await ws.close()

    async def test_malformed_json_and_unexpected_command_closed(self):
        ws, _ = await self.open_device()
        try:
            await ws.send("not-json")
            with self.assertRaises(ConnectionClosed):
                await ws.recv()
        finally:
            await ws.close()
        ws, _ = await self.open_device()
        try:
            await ws.send(json.dumps({"type": "dangerous-write"}))
            with self.assertRaises(ConnectionClosed):
                await ws.recv()
            self.assertEqual(self.gateway.denied_calls, 1)
        finally:
            await ws.close()

    async def test_mcp_untrusted_unknown_id_dropped(self):
        ws, _ = await self.open_device()
        try:
            payload = {"jsonrpc": "2.0", "id": 12345, "result": {"tools": []}}
            await ws.send(json.dumps({"type": "mcp", "payload": payload}))
            await ws.send(json.dumps({"type": "mcp", "payload": {**payload, "id": 1}}))
            await asyncio.sleep(0.05)
            # The gateway never asked this device for any tools.
            self.assertEqual(self.gateway.mcp_dropped, 2)
            self.assertEqual(self.gateway.mcp_accepted, 0)
        finally:
            await ws.close()


    async def test_live_mcp_modern_discovery_and_pagination(self):
        ws, _ = await self.open_device({**HELLO, "features": {"mcp": True, "mcp_20260728": True}})
        try:
            discover = json.loads(await ws.recv())["payload"]
            self.assertEqual(discover["method"], "server/discover")
            self.assertEqual(discover["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
            await ws.send(json.dumps({"type": "mcp", "payload": {
                "jsonrpc": "2.0", "id": discover["id"],
                "result": {"resultType": "complete", "supportedVersions": ["2026-07-28", "2024-11-05"]}}}))
            listing = json.loads(await ws.recv())["payload"]
            self.assertEqual(listing["method"], "tools/list")
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": listing["id"],
                             "result": {"tools": [{"name": "self.audio_speaker.set_volume"}], "nextCursor": "c2"}}}))
            page2 = json.loads(await ws.recv())["payload"]
            self.assertEqual(page2["params"]["cursor"], "c2")
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": page2["id"],
                             "result": {"tools": []}}}))
            await asyncio.sleep(0.04)
            self.assertEqual(self.gateway.mcp_accepted, 3)
            self.assertEqual(self.gateway.mcp_dropped, 0)
        finally:
            await ws.close()

    async def test_live_mcp_legacy_initialize(self):
        ws, _ = await self.open_device({**HELLO, "features": {"mcp": True}})
        try:
            initial = json.loads(await ws.recv())["payload"]
            self.assertEqual(initial["method"], "initialize")
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": initial["id"],
                      "result": {"protocolVersion": "2024-11-05", "capabilities": {}}}}))
            listing = json.loads(await ws.recv())["payload"]
            self.assertEqual(listing["method"], "tools/list")
            self.assertNotIn("_meta", listing["params"])
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": listing["id"],
                      "result": {"tools": []}}}))
            await asyncio.sleep(0.04)
            self.assertEqual(self.gateway.mcp_accepted, 2)
        finally:
            await ws.close()

    async def test_live_mcp_modern_method_not_found_legacy_fallback(self):
        ws, _ = await self.open_device({**HELLO, "features": {"mcp": True, "mcp_20260728": True}})
        try:
            initial = json.loads(await ws.recv())["payload"]
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": initial["id"],
                      "error": {"code": -32601, "message": "not found"}}}))
            fallback = json.loads(await ws.recv())["payload"]
            self.assertEqual(fallback["method"], "initialize")
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": fallback["id"],
                      "result": {"protocolVersion": "2024-11-05", "capabilities": {}}}}))
            listing = json.loads(await ws.recv())["payload"]
            self.assertEqual(listing["method"], "tools/list")
            await ws.send(json.dumps({"type": "mcp", "payload": {"jsonrpc": "2.0", "id": listing["id"],
                      "result": {"tools": []}}}))
            await asyncio.sleep(0.04)
            self.assertEqual(self.gateway.mcp_accepted, 3)
        finally:
            await ws.close()

    async def test_malformed_binary_refused(self):
        ws, _ = await self.open_device()
        try:
            await ws.send(struct.pack("!BBH", 0, 0, 1000) + b"short")
            with self.assertRaises(ConnectionClosed):
                await ws.recv()
        finally:
            await ws.close()


if __name__ == "__main__":
    credential_guard()
    unittest.main()