import { Plugin } from "@opencode/plugin"
import {
  applyPermissionDecision,
  callGuard,
  permissionPayload,
  toolPayload,
} from "./guard-client.js"

export default Plugin.define({
  id: "agent-guardrail",
  async setup(ctx) {
    const cwd = ctx.location.directory

    // This is the three-state integration. OpenCode invokes it after its own
    // configured rules and before an action or approval prompt is published.
    await ctx.permission.hook("evaluate", async (event) => {
      try {
        const decision = await callGuard(permissionPayload(event, cwd))
        applyPermissionDecision(event, decision)
      } catch (error) {
        event.effect = "deny"
        event.message = String(error?.message ?? error)
      }
    })

    // Re-check the complete structured tool input at the execution boundary.
    // A hard block discovered here is enforceable. Approval-class decisions
    // are left to the permission hook above because this late hook cannot open
    // a permission prompt.
    await ctx.tool.hook("execute.before", async (event) => {
      let decision
      try {
        decision = await callGuard(toolPayload(event, cwd))
      } catch (error) {
        throw new Error(String(error?.message ?? error))
      }
      if (decision.decision === "block") {
        throw new Error(decision.reason ?? "Blocked by Agent Guardrail")
      }
    })
  },
})
