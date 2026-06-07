/**
 * Before Tool Guard — OpenClaw Plugin
 *
 * Bridges tool-call decisions to a local Python guard service at
 * http://127.0.0.1:8765/evaluate_tool_call.
 *
 * Uses the official OpenClaw plugin SDK with the correct
 * before_tool_call hook event shape and return contract.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const DEFAULT_GUARD_URL = "http://127.0.0.1:8765/evaluate_tool_call";

type GuardDecision = {
  decision: "allow" | "block" | "approval_required" | string;
  reason?: string;
  risk?: string;
  approval_id?: string;
};

async function callPythonGuard(
  toolName: string,
  params: Record<string, unknown>,
  sessionId?: string,
  userId?: string,
  channel?: string,
): Promise<GuardDecision> {
  const guardUrl = process.env.TOOL_GUARD_URL || DEFAULT_GUARD_URL;

  const payload = {
    tool_name: toolName,
    arguments: params,
    session_id: sessionId ?? null,
    user_id: userId ?? null,
    source: channel ?? null,
  };

  const response = await fetch(guardUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    return {
      decision: "block",
      reason: `Python guard returned HTTP ${response.status}`,
    };
  }

  return (await response.json()) as GuardDecision;
}

export default definePluginEntry({
  id: "before-tool-guard",
  name: "Before Tool Guard",
  description: "Blocks or escalates risky tool calls by consulting a local Python guard service.",
  register(api) {
    api.on(
      "before_tool_call",
      async (event) => {
        const toolName = event.toolName;
        const params = event.params ?? {};

        // Extract context fields for the guard payload
        const ctx = (event as any).context ?? (event as any).ctx ?? {};
        const sessionId = ctx.sessionId ?? ctx.session_id ?? null;
        const userId = ctx.userId ?? ctx.user_id ?? null;
        const channel = ctx.channel ?? ctx.source ?? null;

        let decision: GuardDecision;
        try {
          decision = await callPythonGuard(toolName, params, sessionId ?? undefined, userId ?? undefined, channel ?? undefined);
        } catch (err: any) {
          // Fail closed: if the guard is unreachable, block the tool call.
          return {
            block: true,
            blockReason: `Blocked by tool guard: Python guard unreachable: ${err?.message || err}`,
          };
        }

        if (decision.decision === "allow") {
          return {}; // pass — no block
        }

        if (decision.decision === "approval_required") {
          return {
            requireApproval: {
              title: `Approve tool call: ${toolName}`,
              description:
                `Risk: ${decision.risk || "unknown"}\n` +
                `Reason: ${decision.reason || "approval required"}\n` +
                `Approval ID: ${decision.approval_id || "none"}`,
              severity: "warning",
              timeoutMs: 60_000,
              timeoutBehavior: "deny",
            },
          };
        }

        // Default: block
        return {
          block: true,
          blockReason: decision.reason || "Blocked by Python tool guard",
        };
      },
      { priority: 100 },
    );
  },
});
