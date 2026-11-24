
from time import perf_counter

from netghost.engine.correlation import correlate_investigation
from netghost.engine.diagnosis import diagnose_investigation
from netghost.engine.planner import create_investigation_plan
from netghost.tools.connections import get_active_connections
from netghost.tools.dns import get_dns_configuration, resolve_domain
from netghost.tools.http import inspect_http
from netghost.tools.interfaces import get_network_interfaces
from netghost.tools.ip_intelligence import lookup_ip_intelligence
from netghost.tools.latency import measure_latency
from netghost.tools.packet_loss import measure_packet_loss
from netghost.tools.routing import trace_route
from netghost.tools.tls import inspect_tls

TOOL_REGISTRY = {
    "netghost_network_interfaces": get_network_interfaces,
    "netghost_dns_configuration": get_dns_configuration,
    "netghost_dns_lookup": resolve_domain,
    "netghost_measure_latency": measure_latency,
    "netghost_measure_packet_loss": measure_packet_loss,
    "netghost_traceroute": trace_route,
    "netghost_active_connections": get_active_connections,
    "netghost_ip_intelligence": lookup_ip_intelligence,
    "netghost_http_inspect": inspect_http,
    "netghost_tls_inspect": inspect_tls,
}



def is_tool_successful(result: dict) -> bool:
    """Distinguish tool execution failures from diagnostic outcomes."""

    execution_status = result.get("execution_status")

    if execution_status is not None:
        return execution_status in {"completed"}

    status = result.get("status")

    if status is not None:
        return status not in {
            "invalid_input",
            "unsupported_platform",
            "error",
        }

    return "interfaces" in result



def get_latency_statistics(result: dict | None) -> dict:
    """Safely retrieve latency statistics from a diagnostic result."""

    if not isinstance(result, dict):
        return {}

    return result.get("statistics", {})


def get_evidence_for_target(evidence: list[dict], tool: str, target: str):
    """Find the most recent result for a particular tool and target."""

    for item in reversed(evidence):
        if item["tool"] != tool:
            continue

        if item["result"].get("target") == target:
            return item["result"]

    return None


def detect_latency_anomaly(
    target_result: dict | None,
    gateway_result: dict | None,
) -> tuple[bool, list[str]]:
    """
    Identify signals that justify deeper investigation.

    These are investigation heuristics, not proof of a fault.
    """

    reasons = []

    target_stats = get_latency_statistics(target_result)
    gateway_stats = get_latency_statistics(gateway_result)

    target_avg = target_stats.get("avg_ms")
    target_loss = target_stats.get("packet_loss_percent")

    gateway_avg = gateway_stats.get("avg_ms")
    gateway_loss = gateway_stats.get("packet_loss_percent")

    if target_result and target_result.get("status") == "unreachable":
        reasons.append("External target did not respond to latency probes")

    if isinstance(target_loss, (int, float)) and target_loss > 0:
        reasons.append(f"External packet loss observed: {target_loss}%")

    if isinstance(gateway_loss, (int, float)) and gateway_loss > 0:
        reasons.append(f"Gateway packet loss observed: {gateway_loss}%")

    if isinstance(gateway_avg, (int, float)) and gateway_avg > 30:
        reasons.append(f"Gateway average latency is elevated: {gateway_avg} ms")

    if isinstance(target_avg, (int, float)):
        if target_avg > 150:
            reasons.append(f"External average latency is high: {target_avg} ms")

        if isinstance(gateway_avg, (int, float)):
            latency_gap = target_avg - gateway_avg

            if latency_gap > 80:
                reasons.append(
                    f"External latency exceeds gateway latency by "
                    f"{round(latency_gap, 2)} ms"
                )

    return bool(reasons), reasons


def should_run_step(
    condition: str,
    evidence: list[dict],
    target: str | None,
) -> tuple[bool, str]:
    """Evaluate a planner condition using collected evidence."""

    if condition == "always":
        return True, "Unconditional step"

    target_latency = (
        get_evidence_for_target(
            evidence,
            "netghost_measure_latency",
            target,
        )
        if target
        else None
    )

    gateway_latency = next(
        (
            item["result"]
            for item in reversed(evidence)
            if item.get("role") == "gateway_latency"
        ),
        None,
    )

    if condition == "if_latency_anomaly":
        anomaly, reasons = detect_latency_anomaly(
            target_latency,
            gateway_latency,
        )

        return anomaly, "; ".join(reasons) if reasons else "No latency anomaly detected"

    if condition == "if_packet_loss_detected":
        loss_result = get_evidence_for_target(
            evidence,
            "netghost_measure_packet_loss",
            target,
        )

        loss = (
            loss_result.get("packet_loss_percent")
            if loss_result
            else None
        )

        detected = isinstance(loss, (int, float)) and loss > 0

        return (
            detected,
            f"Packet loss detected: {loss}%"
            if detected
            else "No packet loss detected",
        )

    if condition == "if_target_unreachable":
        unreachable = (
            target_latency is not None
            and target_latency.get("status") == "unreachable"
        )

        return (
            unreachable,
            "Target did not respond"
            if unreachable
            else "Target responded to latency probes",
        )

    return False, f"Unknown execution condition: {condition}"


def execute_step(step: dict) -> dict:
    """Execute one diagnostic step and isolate tool failures."""

    tool_name = step["tool"]
    arguments = step["arguments"]

    tool_function = TOOL_REGISTRY.get(tool_name)

    if tool_function is None:
        return {
            "execution_status": "error",
            "error": f"Unknown diagnostic tool: {tool_name}",
        }

    try:
        result = tool_function(**arguments)

        if not isinstance(result, dict):
            return {
                "execution_status": "error",
                "error": "Diagnostic tool returned an unexpected result",
            }

        return result

    except Exception as exc:  # noqa: BLE001
        return {
            "execution_status": "error",
            "error": str(exc),
        }


def execute_gateway_latency(
    interfaces_result: dict,
) -> dict | None:
    """Measure latency to the default gateway when one is available."""

    gateway = interfaces_result.get("default_gateway")

    if not gateway:
        return None

    return measure_latency(
        target=gateway,
        count=5,
        interval=0.2,
        timeout=2.0,
    )


def investigate_network(
    symptom: str,
    target: str | None = None,
    domain: str | None = None,
    max_steps: int = 8,
) -> dict:
    """
    Execute a planned network investigation.

    Collects evidence, evaluates conditional steps, and records
    every execution decision.
    """

    if not isinstance(max_steps, int) or max_steps < 1:
        return {
            "status": "invalid_input",
            "error": "max_steps must be a positive integer",
        }

    plan = create_investigation_plan(
        symptom=symptom,
        target=target,
        domain=domain,
    )

    if plan["status"] != "ready":
        return {
            "status": plan["status"],
            "plan": plan,
            "evidence": [],
            "trace": [],
        }

    evidence = []
    trace = []
    started_at = perf_counter()
    executed_steps = 0

    for step in plan["steps"]:

        if executed_steps >= max_steps:
            trace.append({
                "tool": step["tool"],
                "status": "skipped",
                "reason": "Execution budget exhausted",
            })
            continue

        should_execute, decision = should_run_step(
            condition=step["run_when"],
            evidence=evidence,
            target=target,
        )

        if not should_execute:
            trace.append({
                "tool": step["tool"],
                "status": "skipped",
                "reason": decision,
            })
            continue

        step_started = perf_counter()
        result = execute_step(step)
        duration_ms = round(
            (perf_counter() - step_started) * 1000,
            3,
        )

        executed_steps += 1

        successful = is_tool_successful(result)

        evidence_item = {
            "tool": step["tool"],
            "purpose": step["purpose"],
            "arguments": step["arguments"],
            "result": result,
            "successful": successful,
        }

        evidence.append(evidence_item)

        trace.append({
            "tool": step["tool"],
            "status": "success" if successful else "error",
            "reason": decision,
            "duration_ms": duration_ms,
        })

        # For slow-internet investigations, compare the gateway
        # against the external target before deciding on deeper tests.
        if (
            plan["category"] == "slow"
            and step["tool"] == "netghost_network_interfaces"
            and successful
            and executed_steps < max_steps
        ):
            gateway_started = perf_counter()

            try:
                gateway_result = execute_gateway_latency(result)
            except Exception as exc:  # noqa: BLE001
                gateway_result = {
                    "status": "error",
                    "error": str(exc),
                }

            if gateway_result is not None:
                gateway_successful = is_tool_successful(gateway_result)

                evidence.append({
                    "tool": "netghost_measure_latency",
                    "role": "gateway_latency",
                    "purpose": "Measure latency to the default gateway",
                    "arguments": {
                        "target": result.get("default_gateway"),
                        "count": 5,
                        "interval": 0.2,
                        "timeout": 2.0,
                    },
                    "result": gateway_result,
                    "successful": gateway_successful,
                })

                trace.append({
                    "tool": "netghost_measure_latency",
                    "role": "gateway_latency",
                    "status": "success" if gateway_successful else "error",
                    "reason": "Establish local-network latency baseline",
                    "duration_ms": round(
                        (perf_counter() - gateway_started) * 1000,
                        3,
                    ),
                })

                executed_steps += 1

    failures = sum(
        not item["successful"]
        for item in evidence
    )

    elapsed_ms = round(
        (perf_counter() - started_at) * 1000,
        3,
    )

    if not evidence:
        status = "failed"
    elif failures == 0:
        status = "completed"
    elif failures == len(evidence):
        status = "failed"
    else:
        status = "partial"

    investigation = {
        "status": status,
        "symptom": symptom,
        "category": plan["category"],
        "target": target,
        "domain": domain,
        "execution": {
            "steps_executed": executed_steps,
            "steps_failed": failures,
            "duration_ms": elapsed_ms,
            "max_steps": max_steps,
        },
        "evidence": evidence,
        "trace": trace,
    }
    investigation["correlations"] = correlate_investigation(investigation)
    investigation["diagnosis"] = diagnose_investigation(investigation)

    return investigation


def register_tools(mcp) -> None:
    """Register the autonomous investigation entry point."""

    @mcp.tool
    def netghost_investigate(
        symptom: str,
        target: str | None = None,
        domain: str | None = None,
    ) -> dict:
        """
        Investigate a network symptom using sequential diagnostics.

        Supported symptoms: slow, dns, packet_loss,
        unreachable, general, network_activity.
        """

        return investigate_network(
            symptom=symptom,
            target=target,
            domain=domain,
        )
