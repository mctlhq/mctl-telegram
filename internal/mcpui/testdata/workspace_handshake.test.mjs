import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { setImmediate } from "node:timers/promises";
import vm from "node:vm";

const html = readFileSync(new URL("../workspace.html", import.meta.url), "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

for (const [version, accepted] of [
  ["2026-01-26", true], ["2025-11-21", true], ["unknown", false], [undefined, false],
]) {
  for (const serverTools of [true, false]) {
    test(`host version ${version}, server tools ${serverTools}`, async () => {
      const sent = [];
      const elements = new Map();
      const document = {
        getElementById(id) {
          if (!elements.has(id)) elements.set(id, { disabled: true, addEventListener() {} });
          return elements.get(id);
        },
        querySelectorAll: () => [],
        querySelector: () => ({}),
      };
      const parent = { postMessage(message) { sent.push(message); } };
      let receive;
      const window = { parent, addEventListener(type, fn) { if (type === "message") receive = fn; } };
      vm.runInNewContext(script, {
        document, window, setTimeout, clearTimeout,
        ResizeObserver: class { observe() {} },
      });
      const [init] = sent;
      assert.equal(init.method, "ui/initialize");
      assert.equal(init.params.protocolVersion, "2026-01-26");
      receive({ source: parent, data: { jsonrpc: "2.0", id: init.id, result: {
        protocolVersion: version, hostCapabilities: serverTools ? { serverTools: {} } : {},
        hostContext: { availableDisplayModes: ["inline"] },
      } } });
      await setImmediate();
      assert.deepEqual(sent.slice(1).map(message => message.method),
        accepted ? ["ui/notifications/initialized"] : []);
      assert.equal(elements.get("refresh").disabled, !(accepted && serverTools));
      assert.equal(elements.get("run-search").disabled, !(accepted && serverTools));
      if (!accepted) assert.equal(elements.get("status").textContent, "Unsupported MCP Apps protocol.");
    });
  }
}
