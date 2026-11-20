"""The egress gateway: the only path from the control plane to a model outside the boundary.

The pipeline never holds the external provider. It holds this gateway, which refuses to
send unless both conditions hold:

1. the policy decision is an action that is meant to leave the boundary, and
2. the destination is on the policy's allowlist.

This is enforcement in code. Enforcing it at the network layer as well (an internal
network whose only route out is an egress proxy) is the next step for a real deployment.
"""

from __future__ import annotations

from control_plane.models import Action, Decision
from control_plane.policy import Policy
from control_plane.providers.base import ModelProvider, ModelReply

EXTERNAL_ACTIONS = frozenset({Action.ALLOW, Action.REDACT})


class EgressDeniedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class EgressGateway:
    def __init__(self, provider: ModelProvider) -> None:
        if provider.in_boundary:
            raise ValueError("the egress gateway fronts an external provider")
        self._provider = provider

    @property
    def provider(self) -> ModelProvider:
        return self._provider

    @property
    def destination(self) -> str:
        return self._provider.name

    def check(self, decision: Decision, policy: Policy) -> None:
        """Raise EgressDeniedError unless `send` would send. Sends nothing.

        Lets the caller record the call before it is made, and only if it will be made.
        """
        if decision.action not in EXTERNAL_ACTIONS:
            raise EgressDeniedError("action_does_not_permit_egress")
        if self.destination not in policy.document.egress.allowed_destinations:
            raise EgressDeniedError("destination_not_allowlisted")

    def send(self, payload: str, decision: Decision, policy: Policy) -> ModelReply:
        """Send `payload` to the external model, or raise EgressDeniedError."""
        # Checked again here, so no caller can send without the check.
        self.check(decision, policy)
        return self._provider.generate(payload)
