"""Request-path visualization model (RT-024).

Builds a linear, render-agnostic view of the externally observable request
path (DNS -> Connectivity -> TLS -> HTTP -> Edge -> Application) from module
results and edge indicators. This is a pure derivation for reporting — it
never claims a hidden/internal service exists, and every stage's status is
explicit rather than implied.
"""

from __future__ import annotations

from dataclasses import dataclass

from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target

_STATUS_LABELS = {
    ModuleStatus.COMPLETED: "Observed",
    ModuleStatus.PARTIAL: "Partially observed",
    ModuleStatus.ERROR: "Not reachable / error",
    ModuleStatus.NOT_TESTED: "Not tested",
    ModuleStatus.SKIPPED: "Not applicable",
}


@dataclass(frozen=True, slots=True)
class PathStage:
    """One node in the rendered request-path diagram."""

    name: str
    status_label: str
    detail: str
    is_inferred: bool


def build_request_path(
    target: Target,
    module_results: list[ModuleResult],
    edge_provider_summary: str | None,
) -> list[PathStage]:
    """Assemble the ordered, render-agnostic request-path stage list."""
    results_by_module = {result.module: result for result in module_results}

    stages = [
        _stage_for_module("Client DNS Resolution", results_by_module.get(ModuleName.DNS), target.host),
        _stage_for_module("TCP Connectivity", results_by_module.get(ModuleName.CONNECTIVITY), target.authority),
    ]

    if target.scheme == "https":
        stages.append(_stage_for_module("TLS Negotiation", results_by_module.get(ModuleName.TLS), target.host))

    stages.append(
        _stage_for_module("HTTP Request/Response", results_by_module.get(ModuleName.HTTP), target.normalized_url)
    )

    if edge_provider_summary:
        stages.append(
            PathStage(
                name="Edge / CDN (inferred)",
                status_label="Inferred from indicators",
                detail=edge_provider_summary,
                is_inferred=True,
            )
        )

    stages.append(
        PathStage(
            name="Origin Application",
            status_label="Not directly observable",
            detail=(
                "RequestTrace cannot see internal services, databases or private network "
                "hops beyond the externally observable HTTP response."
            ),
            is_inferred=True,
        )
    )

    return stages


def _stage_for_module(name: str, module_result: ModuleResult | None, detail_target: str) -> PathStage:
    if module_result is None:
        return PathStage(name=name, status_label="Not tested", detail=detail_target, is_inferred=False)
    label = _STATUS_LABELS.get(module_result.status, module_result.status.value)
    return PathStage(name=name, status_label=label, detail=detail_target, is_inferred=False)
