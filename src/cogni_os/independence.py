"""Agent identity declarations and independent-verification checks for Cogni-OS."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from .errors import ConfigurationError
from .util import validate_agent_id

IDENTITY_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def validate_identity_value(value: str, *, field: str) -> str:
    """Validate one stable identity label used in signed policy decisions."""
    normalized = value.strip()
    if not IDENTITY_VALUE_RE.fullmatch(normalized):
        raise ConfigurationError(
            f"{field} must start with an alphanumeric character and contain only "
            "letters, numbers, dot, underscore, colon, slash, or hyphen "
            "(maximum 128 characters)"
        )
    return normalized


def build_identity(
    *,
    control_principal: str,
    model_family: str,
    alias_of: str | None = None,
    alias_chain: list[str] | None = None,
) -> dict[str, Any]:
    """Build a validated, flattenable agent identity declaration."""
    normalized_alias = validate_agent_id(alias_of) if alias_of else None
    normalized_chain = [
        validate_agent_id(item) for item in (alias_chain or [])
    ]
    if len(normalized_chain) != len(set(normalized_chain)):
        raise ConfigurationError("Agent identity alias chain contains a cycle")
    return {
        "schema_version": 1,
        "control_principal": validate_identity_value(
            control_principal,
            field="control_principal",
        ),
        "model_family": validate_identity_value(
            model_family,
            field="model_family",
        ),
        "alias_of": normalized_alias,
        "alias_chain": normalized_chain,
    }


def identity_snapshot(
    actor: str,
    identity: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Return the semantic identity fields bound to a task transition."""
    if not isinstance(identity, dict):
        return None
    validated = build_identity(
        control_principal=str(identity.get("control_principal", "")),
        model_family=str(identity.get("model_family", "")),
        alias_of=identity.get("alias_of"),
        alias_chain=list(identity.get("alias_chain", [])),
    )
    return {
        "actor": validate_agent_id(actor),
        **validated,
    }


def evaluate_independence(
    worker: dict[str, Any] | None,
    verifier: dict[str, Any] | None,
) -> dict[str, Any]:
    """Conservatively decide whether two signed identity snapshots are independent."""
    reasons: list[str] = []
    if worker is None:
        reasons.append("worker_identity_unknown")
    if verifier is None:
        reasons.append("verifier_identity_unknown")
    if worker is not None and verifier is not None:
        if (
            worker.get("actor") is not None
            and worker.get("actor") == verifier.get("actor")
        ):
            reasons.append("same_actor")
        if worker.get("control_principal") == verifier.get("control_principal"):
            reasons.append("same_control_principal")
        if worker.get("model_family") == verifier.get("model_family"):
            reasons.append("same_model_family")
        worker_lineage = set(map(str, worker.get("alias_chain", [])))
        verifier_lineage = set(map(str, verifier.get("alias_chain", [])))
        if worker.get("actor") is not None:
            worker_lineage.add(str(worker["actor"]))
        if verifier.get("actor") is not None:
            verifier_lineage.add(str(verifier["actor"]))
        if worker_lineage & verifier_lineage:
            reasons.append("shared_alias_lineage")
    return {
        "independent": not reasons,
        "reasons": reasons,
        "worker": deepcopy(worker),
        "verifier": deepcopy(verifier),
    }


def _policy_agents(policy: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if policy is None:
        return {}
    agents = policy.get("agents")
    if not isinstance(agents, dict):
        raise ConfigurationError("Identity policy must contain an 'agents' object")
    return {
        validate_agent_id(str(agent_id)): deepcopy(identity)
        for agent_id, identity in agents.items()
        if isinstance(identity, dict)
    }


def resolve_identity_registry(
    agents: dict[str, dict[str, Any]],
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any] | None]:
    """Resolve signed identities plus optional read-only legacy audit overrides."""
    declarations: dict[str, dict[str, Any] | None] = {
        agent_id: deepcopy(record.get("identity"))
        if isinstance(record.get("identity"), dict)
        else None
        for agent_id, record in agents.items()
    }
    for agent_id, policy_identity in _policy_agents(policy).items():
        if declarations.get(agent_id) is None:
            declarations[agent_id] = policy_identity
    resolved: dict[str, dict[str, Any] | None] = {}

    def resolve(agent_id: str, stack: tuple[str, ...] = ()) -> dict[str, Any] | None:
        if agent_id in resolved:
            return resolved[agent_id]
        if agent_id in stack:
            raise ConfigurationError(
                "Identity policy alias cycle: " + " -> ".join((*stack, agent_id))
            )
        declaration = declarations.get(agent_id)
        if declaration is None:
            resolved[agent_id] = None
            return None
        alias_of = declaration.get("alias_of")
        if alias_of:
            target_id = validate_agent_id(str(alias_of))
            target = resolve(target_id, (*stack, agent_id))
            if target is None:
                resolved[agent_id] = None
                return None
            value = build_identity(
                control_principal=target["control_principal"],
                model_family=target["model_family"],
                alias_of=target_id,
                alias_chain=[target_id, *target.get("alias_chain", [])],
            )
        else:
            value = build_identity(
                control_principal=str(declaration.get("control_principal", "")),
                model_family=str(declaration.get("model_family", "")),
                alias_chain=list(declaration.get("alias_chain", [])),
            )
        resolved[agent_id] = identity_snapshot(agent_id, value)
        return resolved[agent_id]

    for agent_id in declarations:
        resolve(agent_id)
    return resolved


def audit_verification_events(
    events: list[dict[str, Any]],
    agents: dict[str, dict[str, Any]],
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Audit historical verification events without modifying the ledger."""
    identities = resolve_identity_registry(agents, policy=policy)
    policy_agents = _policy_agents(policy)
    policy_filled = {
        agent_id
        for agent_id in policy_agents
        if not isinstance(agents.get(agent_id, {}).get("identity"), dict)
    }

    def current_source(actor: str) -> str:
        if isinstance(agents.get(actor, {}).get("identity"), dict):
            return "agent_declaration"
        if actor in policy_filled:
            return "policy_override"
        return "missing"

    audited_verifications: list[dict[str, Any]] = []
    audited_submissions: list[dict[str, Any]] = []
    task_submissions: dict[str, dict[str, Any]] = {}

    for event in events:
        action = event.get("action")
        task_id = str(event.get("task_id", ""))
        actor = str(event.get("actor", ""))
        if action == "task.submitted":
            worker_identity = event.get("payload", {}).get("worker_identity")
            if not isinstance(worker_identity, dict):
                worker_identity = identities.get(actor)
            submission_record = {
                "sequence": event.get("sequence"),
                "task_id": task_id,
                "actor": actor,
                "worker_identity": deepcopy(worker_identity),
            }
            task_submissions[task_id] = submission_record
            audited_submissions.append(submission_record)
        elif action == "task.verified":
            verifier_identity = event.get("payload", {}).get("verifier_identity")
            if not isinstance(verifier_identity, dict):
                verifier_identity = identities.get(actor)
            submission = task_submissions.get(task_id)
            worker_identity = submission.get("worker_identity") if submission else None
            worker_actor = submission.get("actor") if submission else None
            eval_result = evaluate_independence(worker_identity, verifier_identity)
            audited_verifications.append({
                "sequence": event.get("sequence"),
                "task_id": task_id,
                "worker_actor": worker_actor,
                "verifier_actor": actor,
                "worker_identity": worker_identity,
                "verifier_identity": verifier_identity,
                "worker_identity_source": current_source(worker_actor) if worker_actor else "missing",
                "verifier_identity_source": current_source(actor),
                "recorded_independence": event.get("payload", {}).get("independence"),
                "audited_independence": eval_result,
            })

    return {
        "valid": True,
        "audited_submissions": len(audited_submissions),
        "audited_verifications": len(audited_verifications),
        "verifications": audited_verifications,
    }
