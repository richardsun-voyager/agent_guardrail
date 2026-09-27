import assert from "node:assert/strict"
import test from "node:test"

import {
  applyPermissionDecision,
  normalizeToolName,
  patchPaths,
  permissionPayload,
  toolPayload,
} from "../src/guard-client.js"

test("normalizes OpenCode tool events", () => {
  assert.equal(normalizeToolName("bash"), "exec")
  const payload = toolPayload(
    { tool: "read", input: { filePath: "README.md" }, sessionID: "s1" },
    "/repo",
  )
  assert.equal(payload.tool_name, "read_file")
  assert.equal(payload.arguments.cwd, "/repo")
  assert.equal(payload.source, "opencode")
})

test("extracts file paths embedded in apply_patch", () => {
  assert.deepEqual(
    patchPaths("*** Begin Patch\n*** Add File: src/new.js\n*** Delete File: old.js\n*** End Patch"),
    ["src/new.js", "old.js"],
  )
})

test("maps guard decisions onto OpenCode effects", () => {
  const ask = { effect: "allow" }
  applyPermissionDecision(ask, {
    decision: "approval_required",
    reason: "review",
    approval_id: "a1",
  })
  assert.equal(ask.effect, "ask")
  assert.match(ask.message, /a1/)

  const deny = { effect: "allow" }
  applyPermissionDecision(deny, { decision: "block", reason: "unsafe" })
  assert.equal(deny.effect, "deny")
})

test("builds permission payload from structured metadata and resources", () => {
  const payload = permissionPayload(
    {
      action: "bash",
      sessionID: "s2",
      resources: ["git push origin main"],
      metadata: { input: { command: "git push origin main" } },
      source: { id: "call-1" },
    },
    "/repo",
  )
  assert.equal(payload.tool_name, "exec")
  assert.equal(payload.arguments.command, "git push origin main")
  assert.equal(payload.tool_call_id, "call-1")
})
