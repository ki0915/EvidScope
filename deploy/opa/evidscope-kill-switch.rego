# Example only (docs/kill-switch.md): how an OPA that pulls the EvidScope bundle (root `evidscope`) can deny tool calls of
# agents that are not in production or are covered by an active stop order. EvidScope is not a policy engine; adapt the
# input shape to your gateway. This file was not parsed by OPA in the EvidScope test suite (no OPA binary is bundled).
#
# input: {"agent": {"source": "<authenticated source principal id>", "actor": "<reported actor name>"}, "tool": "<tool name>"}
package killswitch

import rego.v1

registry := data.evidscope

# The registry entry of the call: by authenticated source principal first, then by the reported actor name.
agent_id := registry.sources[input.agent.source]

agent_id := registry.actors[input.agent.actor] if {
	not registry.sources[input.agent.source]
}

agent := registry.agents[agent_id]

deny contains "agent_not_registered" if not agent_id

# A name that resolves to an entry the bundle does not carry is denied, never allowed by default.
deny contains "agent_not_in_bundle" if {
	agent_id
	not agent
}

deny contains sprintf("agent_state_%s", [agent.state]) if agent.state != "production"

deny contains sprintf("stop_order_%s", [order]) if {
	agent.stopped
	some order in agent.stop_orders
	registry.stop_orders[order].scope == "agent"
}

deny contains sprintf("tool_stopped_%s", [input.tool]) if input.tool in agent.stopped_tools

default allow := false

allow if count(deny) == 0

# Named in decision logs so a decision can be tied to the revision (and so to the stop orders) it was made under.
bundle_revision := registry.revision
