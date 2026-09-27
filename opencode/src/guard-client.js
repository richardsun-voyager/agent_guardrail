const DEFAULT_URL = "http://127.0.0.1:8765/evaluate_tool_call"

const TOOL_NAMES = {
  bash: "exec",
  read: "read_file",
  write: "write_file",
  edit: "edit",
  apply_patch: "apply_patch",
  webfetch: "web_fetch",
  websearch: "web_search",
}

export function normalizeToolName(name) {
  const value = String(name ?? "")
  return TOOL_NAMES[value.toLowerCase()] ?? value
}

export function patchPaths(command) {
  if (typeof command !== "string") return []
  const prefixes = ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "]
  return command.split(/\r?\n/).flatMap((line) => {
    const prefix = prefixes.find((candidate) => line.startsWith(candidate))
    if (!prefix) return []
    const path = line.slice(prefix.length).trim()
    return path ? [path] : []
  })
}

export function toolPayload(event, cwd) {
  const input = event?.input
  const arguments_ = input && typeof input === "object" && !Array.isArray(input)
    ? { ...input }
    : { input }
  if (String(event?.tool).toLowerCase() === "apply_patch" && arguments_.path === undefined) {
    const paths = patchPaths(arguments_.patchText ?? arguments_.command)
    if (paths.length) arguments_.path = paths
  }
  if (cwd && arguments_.cwd === undefined) arguments_.cwd = cwd
  return {
    tool_name: normalizeToolName(event?.tool),
    arguments: arguments_,
    session_id: event?.sessionID ?? null,
    tool_call_id: event?.callID ?? event?.id ?? null,
    source: "opencode",
  }
}

export function permissionPayload(event, cwd) {
  const metadata = event?.metadata && typeof event.metadata === "object"
    ? event.metadata
    : {}
  const nestedInput = metadata.input && typeof metadata.input === "object"
    ? metadata.input
    : {}
  const toolName = normalizeToolName(event?.action)
  const resources = Array.from(event?.resources ?? [])
  const arguments_ = {
      ...metadata,
      ...nestedInput,
      resources,
      cwd,
  }
  if (["read_file", "write_file", "edit", "apply_patch"].includes(toolName) && arguments_.path === undefined) {
    arguments_.path = resources
  }
  if (toolName === "exec" && arguments_.command === undefined && resources.length) {
    arguments_.command = resources[0]
  }
  if (["web_fetch", "web_search"].includes(toolName) && arguments_.url === undefined && resources.length) {
    arguments_.url = resources[0]
  }
  return {
    tool_name: toolName,
    arguments: arguments_,
    session_id: event?.sessionID ?? null,
    tool_call_id: event?.source?.id ?? null,
    source: "opencode",
  }
}

export async function callGuard(payload, options = {}) {
  const url = options.url ?? process.env.TOOL_GUARD_URL ?? DEFAULT_URL
  const timeout = Number(options.timeout ?? process.env.TOOL_GUARD_TIMEOUT_MS ?? 5000)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const result = await response.json()
    if (!result || !["allow", "approval_required", "block"].includes(result.decision)) {
      throw new Error("invalid decision")
    }
    return result
  } catch (error) {
    throw new Error(`Agent Guardrail unavailable: ${error?.message ?? error}`)
  } finally {
    clearTimeout(timer)
  }
}

export function applyPermissionDecision(event, decision) {
  if (decision.decision === "allow") return
  event.effect = decision.decision === "approval_required" ? "ask" : "deny"
  event.message = decision.approval_id
    ? `${decision.reason ?? "Approval required"} (approval ID: ${decision.approval_id})`
    : decision.reason ?? "Blocked by Agent Guardrail"
}
