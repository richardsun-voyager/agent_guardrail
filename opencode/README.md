# OpenCode Agent Guardrail

This OpenCode v2 plugin connects both relevant policy boundaries to the shared
Agent Guardrail service:

- `permission.evaluate` leaves an `allow` result in OpenCode's existing native
  permission flow, maps `approval_required` to `ask`, and maps `block` to `deny`.
- `tool.execute.before` rechecks the complete structured tool input and vetoes
  hard blocks before execution.

The second check catches detail that may not be present in a permission event.
Since an execution hook cannot create a permission prompt, approval-class
results discovered only at that late boundary are not promoted there; configure
OpenCode permissions so sensitive actions reach `permission.evaluate`.

## Install

Start the service for the protected project:

```bash
export TOOL_GUARD_WORKSPACE=/absolute/path/to/project
python3 before-tool-guard-service/tool_guard_service.py
```

Either copy this folder under `.opencode/plugins/agent-guardrail` or add its
absolute/local path to the `plugins` array in `opencode.jsonc`. OpenCode installs
the declared `@opencode/plugin` dependency with Bun. Override the default local
endpoint with `TOOL_GUARD_URL` when needed.

Run the dependency-free client tests with:

```bash
node opencode/test/guard-client.test.js
```

Service errors and malformed responses deny at the permission boundary. Keep
OpenCode's own permission rules, sandboxing, and OS isolation enabled.
