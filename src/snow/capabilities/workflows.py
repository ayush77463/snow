"""Declarative, bounded multi-step workflow orchestrator for SNOW.

Executes predefined workflows through CapabilityEngine and ApprovalPolicyEngine.
Strictly prohibits arbitrary script execution, shell execution, expression evaluation,
or dynamic imports. Enforces least-privilege principal boundaries, fail-fast behavior,
step-level auditing, and approval pauses.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from snow.capabilities.engine import CapabilityRequest, CapabilityResponse
from snow.security.context import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)

MAX_WORKFLOW_STEPS = 10
MAX_WORKFLOW_TIMEOUT_SECONDS = 120.0


@dataclass
class WorkflowStep:
    """Declarative specification for a single workflow step."""

    step_id: str
    capability: str
    name: str
    description: str
    target_device: Optional[str] = None
    params_template: dict[str, Any] = field(default_factory=dict)
    is_mutating: bool = False
    requires_approval: bool = False

    def __post_init__(self) -> None:
        from snow.mcp.registry import CAPABILITY_REGISTRY
        norm = self.capability if self.capability.startswith("snow_") else f"snow_{self.capability}"
        if norm not in CAPABILITY_REGISTRY and self.capability not in CAPABILITY_REGISTRY:
            raise ValueError(f"Disallowed capability '{self.capability}' in WorkflowStep: must be a registered capability.")


@dataclass
class WorkflowDefinition:
    """Immutable specification for a registered workflow."""

    workflow_id: str
    name: str
    description: str
    steps: list[WorkflowStep]
    is_mutating: bool = False
    requires_approval: bool = False
    max_timeout_seconds: float = 60.0


@dataclass
class WorkflowStepResult:
    """Execution telemetry and outcome for a single workflow step."""

    step_id: str
    order: int
    capability: str
    name: str
    status: str  # "SUCCESS", "FAILED", "PENDING_APPROVAL", "SKIPPED", "CANCELLED"
    start_time: str
    finish_time: str
    duration_seconds: float
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    approval_request: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowExecutionReport:
    """Structured report returned upon workflow execution."""

    workflow_id: str
    name: str
    status: str  # "COMPLETED", "PARTIAL", "FAILED", "PENDING_APPROVAL", "CANCELLED"
    start_time: str
    finish_time: str
    total_duration_seconds: float
    current_step_index: int
    total_steps: int
    step_results: list[dict[str, Any]]
    final_output: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -----------------------------------------------------------------------------
# Workflow Presets
# -----------------------------------------------------------------------------

PRESET_DEVICE_HEALTH = WorkflowDefinition(
    workflow_id="device_health_snapshot",
    name="Device Health Snapshot",
    description="Collect Windows and connected phone system health, battery, and transport diagnostics.",
    steps=[
        WorkflowStep(
            step_id="step_windows_telemetry",
            capability="windows_system_info",
            name="Windows System Info",
            description="Collect Windows OS, CPU, RAM, and load metrics.",
            is_mutating=False,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_device_status",
            capability="list_devices",
            name="Connected Devices Status",
            description="Verify reachability and transport state of connected peer nodes.",
            is_mutating=False,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_phone_battery",
            capability="android_battery",
            name="Phone Battery Status",
            description="Query connected Android phone battery level and charging state.",
            target_device="android",
            is_mutating=False,
            requires_approval=False,
        ),
    ],
    is_mutating=False,
    requires_approval=False,
    max_timeout_seconds=30.0,
)

PRESET_CAPTURE_PC_TO_PHONE = WorkflowDefinition(
    workflow_id="capture_pc_to_phone",
    name="Capture PC Screen → Phone",
    description="Capture the primary Windows display and deliver the screenshot to the connected phone.",
    steps=[
        WorkflowStep(
            step_id="step_capture_screen",
            capability="windows_screenshot",
            name="Capture Windows Display",
            description="Acquire and encode the primary desktop screen as a bounded PNG.",
            is_mutating=False,
            requires_approval=True,
        ),
        WorkflowStep(
            step_id="step_deliver_to_phone",
            capability="android_file_send",
            name="Deliver Image to Phone",
            description="Transfer the staged screenshot PNG to the connected Android device.",
            target_device="android",
            is_mutating=True,
            requires_approval=True,
        ),
    ],
    is_mutating=True,
    requires_approval=True,
    max_timeout_seconds=45.0,
)

PRESET_SHARE_CLIPBOARD = WorkflowDefinition(
    workflow_id="share_clipboard_and_notify",
    name="Share Clipboard & Notify",
    description="Synchronize active clipboard text between devices and record a redacted completion event.",
    steps=[
        WorkflowStep(
            step_id="step_read_clipboard",
            capability="windows_clipboard_get",
            name="Read Windows Clipboard",
            description="Safely inspect local clipboard availability.",
            is_mutating=False,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_record_audit",
            capability="activity_history",
            name="Audit Verification",
            description="Record a secret-redacted completion audit record.",
            params_template={"limit": 1},
            is_mutating=False,
            requires_approval=False,
        ),
    ],
    is_mutating=False,
    requires_approval=False,
    max_timeout_seconds=20.0,
)

PRESET_PC_SCREENSHOT = WorkflowDefinition(
    workflow_id="pc_screenshot",
    name="Capture PC Screen",
    description="Capture the primary Windows display screen and stage as an encoded PNG.",
    steps=[
        WorkflowStep(
            step_id="step_pc_screenshot",
            capability="windows_screenshot",
            name="Capture PC Screenshot",
            description="Acquire and encode desktop screen as a bounded PNG.",
            is_mutating=False,
            requires_approval=True,
        ),
    ],
    is_mutating=False,
    requires_approval=True,
    max_timeout_seconds=30.0,
)

# Immutable fixed registry of allowable workflows
WORKFLOW_REGISTRY: dict[str, WorkflowDefinition] = {
    PRESET_DEVICE_HEALTH.workflow_id: PRESET_DEVICE_HEALTH,
    PRESET_CAPTURE_PC_TO_PHONE.workflow_id: PRESET_CAPTURE_PC_TO_PHONE,
    PRESET_SHARE_CLIPBOARD.workflow_id: PRESET_SHARE_CLIPBOARD,
    PRESET_PC_SCREENSHOT.workflow_id: PRESET_PC_SCREENSHOT,
}


class WorkflowOrchestrator:
    """Declarative workflow execution engine delegating all actions to CapabilityEngine."""

    def __init__(self, capability_engine: Any) -> None:
        self.capability_engine = capability_engine

    def _find_connected_android_device_id(self) -> Optional[str]:
        """Find an active connected Android node from NodeRegistry or SessionRouter."""
        node_reg = getattr(self.capability_engine, "node_registry", None)
        if not node_reg and hasattr(self.capability_engine, "session_router"):
            sr = getattr(self.capability_engine, "session_router", None)
            if sr:
                node_reg = getattr(sr, "node_registry", None)

        if node_reg and hasattr(node_reg, "list_nodes"):
            nodes = node_reg.list_nodes()

            def _is_android(node: Any) -> bool:
                plat = str(getattr(node, "platform", "") or "").lower()
                dev_type = str(getattr(node, "device_type", "") or "").lower()
                name = str(getattr(node, "device_name", "") or "").lower()
                dev_id = str(getattr(node, "device_id", "") or "").lower()
                return (
                    plat == "android"
                    or dev_type in ("android", "phone")
                    or "android" in name
                    or "realme" in name
                    or "phone" in name
                    or "android" in dev_id
                )

            # Pass 1: connected / reachable android nodes
            for n in nodes:
                if _is_android(n):
                    if getattr(n, "is_connected", False):
                        return n.device_id
                    reach = getattr(n, "reachability", None) or getattr(n, "reachability_state", None)
                    st_val = str(getattr(reach, "value", reach) or "").upper()
                    if "ONLINE" in st_val or "REACHABLE" in st_val or "CONNECTED" in st_val:
                        return n.device_id

            # Pass 2: any android node
            for n in nodes:
                if _is_android(n):
                    return n.device_id
        return None

    def list_workflows(self) -> list[dict[str, Any]]:
        """List all available workflow presets and their metadata."""
        return [
            {
                "workflow_id": wf.workflow_id,
                "name": wf.name,
                "description": wf.description,
                "is_mutating": wf.is_mutating,
                "requires_approval": wf.requires_approval,
                "step_count": len(wf.steps),
                "steps": [
                    {
                        "step_id": s.step_id,
                        "name": s.name,
                        "capability": s.capability,
                        "is_mutating": s.is_mutating,
                        "requires_approval": s.requires_approval,
                    }
                    for s in wf.steps
                ],
            }
            for wf in WORKFLOW_REGISTRY.values()
        ]

    def get_workflow(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Retrieve workflow definition by ID."""
        return WORKFLOW_REGISTRY.get((workflow_id or "").strip())

    async def run_workflow(
        self,
        workflow_id: str,
        params: Optional[dict[str, Any]] = None,
        ctx: Optional[ExecutionContext] = None,
    ) -> WorkflowExecutionReport:
        """Execute a declared workflow in sequential steps through CapabilityEngine.

        Args:
            workflow_id: Registered preset identifier.
            params: Optional caller arguments mapped to steps.
            ctx: ExecutionContext (derives caller principal, e.g. OWNER_MANUAL or AI_MCP).

        Returns:
            Structured WorkflowExecutionReport.
        """
        effective_ctx = ctx or ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP, origin="workflow_default"
        )
        wf = self.get_workflow(workflow_id)
        if not wf:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return WorkflowExecutionReport(
                workflow_id=workflow_id or "unknown",
                name="Unknown Workflow",
                status="FAILED",
                start_time=now_iso,
                finish_time=now_iso,
                total_duration_seconds=0.0,
                current_step_index=0,
                total_steps=0,
                step_results=[],
                error=f"Workflow '{workflow_id}' is not registered. Allowed: {list(WORKFLOW_REGISTRY.keys())}",
            )

        start_time_mono = time.monotonic()
        start_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        step_results: list[WorkflowStepResult] = []
        overall_status = "COMPLETED"
        overall_error: Optional[str] = None
        accumulated_data: dict[str, Any] = {}

        input_params = dict(params or {})
        # Strip spoofable security keys
        input_params.pop("principal", None)
        input_params.pop("trust_tier", None)
        input_params.pop("execution_principal", None)

        approval_id = input_params.get("approval_id")

        for idx, step in enumerate(wf.steps):
            step_order = idx + 1
            step_start_mono = time.monotonic()
            step_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Merge step template with validated parameters
            step_params = dict(step.params_template)
            # Propagate outputs from previous steps when relevant
            if step.step_id == "step_deliver_to_phone" and "step_capture_screen" in accumulated_data:
                cap_data = accumulated_data["step_capture_screen"]
                if "file_path" in cap_data:
                    step_params["file_path"] = cap_data["file_path"]
                if "file_name" in cap_data:
                    step_params["file_name"] = cap_data["file_name"]
                if "sha256" in cap_data:
                    step_params["sha256"] = cap_data["sha256"]
                if "transfer_id" in cap_data:
                    step_params["transfer_id"] = cap_data["transfer_id"]

            if approval_id:
                step_params["approval_id"] = approval_id

            target_dev = step.target_device or input_params.get("target_device")

            # Check if workflow timeout exceeded
            if (time.monotonic() - start_time_mono) > wf.max_timeout_seconds:
                overall_status = "FAILED"
                overall_error = f"Workflow exceeded timeout limit ({wf.max_timeout_seconds}s)."
                step_results.append(
                    WorkflowStepResult(
                        step_id=step.step_id,
                        order=step_order,
                        capability=step.capability,
                        name=step.name,
                        status="CANCELLED",
                        start_time=step_start_iso,
                        finish_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        duration_seconds=0.0,
                        error="Cancelled due to workflow timeout.",
                    )
                )
                break

            # Resolve dynamic Android target device ID when available
            if target_dev == "android":
                actual_android_id = self._find_connected_android_device_id()
                if actual_android_id:
                    target_dev = actual_android_id
                    step_params["device_id"] = actual_android_id

            # Execute step through CapabilityEngine
            req = CapabilityRequest(
                action=step.capability,
                params=step_params,
                target_device=target_dev,
            )

            try:
                resp: CapabilityResponse = await self.capability_engine.execute(req, ctx=effective_ctx)
            except Exception as step_exc:
                resp = CapabilityResponse(
                    success=False,
                    status="STEP_EXCEPTION",
                    error=f"Step execution error: {step_exc}",
                )

            step_finish_mono = time.monotonic()
            step_finish_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            duration = step_finish_mono - step_start_mono

            if resp.status == "APPROVAL_REQUIRED":
                # Workflow paused awaiting human owner approval
                app_data = resp.data if isinstance(resp.data, dict) else {}
                step_results.append(
                    WorkflowStepResult(
                        step_id=step.step_id,
                        order=step_order,
                        capability=step.capability,
                        name=step.name,
                        status="PENDING_APPROVAL",
                        start_time=step_start_iso,
                        finish_time=step_finish_iso,
                        duration_seconds=duration,
                        approval_request=app_data,
                        error=resp.error,
                    )
                )
                overall_status = "PENDING_APPROVAL"
                overall_error = f"Workflow paused at step '{step.name}' awaiting owner approval."
                break

            elif not resp.success:
                # If non-critical cross-device peer is offline, mark as PARTIAL instead of failing entire workflow
                is_optional_peer_step = step.step_id in ("step_phone_battery", "step_deliver_to_phone") and resp.status in (
                    "DEVICE_NOT_FOUND",
                    "NO_DEVICES_PAIRED",
                    "ROUTER_UNAVAILABLE",
                    "PEER_OFFLINE",
                    "OFFLINE",
                    "DEVICE_OFFLINE",
                    "DEVICE_UNREACHABLE",
                )
                if is_optional_peer_step:
                    step_results.append(
                        WorkflowStepResult(
                            step_id=step.step_id,
                            order=step_order,
                            capability=step.capability,
                            name=step.name,
                            status="SKIPPED",
                            start_time=step_start_iso,
                            finish_time=step_finish_iso,
                            duration_seconds=duration,
                            data={"status": resp.status, "message": "Phone is offline or unreachable; diagnostics unavailable."},
                            error=resp.error,
                        )
                    )
                    overall_status = "PARTIAL"
                    continue

                # Step failed: record failure and fail-fast
                step_results.append(
                    WorkflowStepResult(
                        step_id=step.step_id,
                        order=step_order,
                        capability=step.capability,
                        name=step.name,
                        status="FAILED",
                        start_time=step_start_iso,
                        finish_time=step_finish_iso,
                        duration_seconds=duration,
                        error=resp.error or f"Capability '{step.capability}' failed with status {resp.status}.",
                    )
                )
                overall_status = "FAILED"
                overall_error = f"Workflow step '{step.name}' failed: {resp.error}"
                break

            else:
                # Step succeeded
                clean_data = resp.data if isinstance(resp.data, dict) else {"result": resp.data}
                # Prevent leaking raw clipboard text
                if "text" in clean_data and step.capability.startswith("windows_clipboard"):
                    clean_data = dict(clean_data)
                    clean_data["text"] = "[REDACTED_CLIPBOARD_TEXT]"

                accumulated_data[step.step_id] = clean_data
                step_results.append(
                    WorkflowStepResult(
                        step_id=step.step_id,
                        order=step_order,
                        capability=step.capability,
                        name=step.name,
                        status="SUCCESS",
                        start_time=step_start_iso,
                        finish_time=step_finish_iso,
                        duration_seconds=duration,
                        data=clean_data,
                    )
                )

        total_duration = time.monotonic() - start_time_mono
        finish_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return WorkflowExecutionReport(
            workflow_id=wf.workflow_id,
            name=wf.name,
            status=overall_status,
            start_time=start_time_iso,
            finish_time=finish_time_iso,
            total_duration_seconds=total_duration,
            current_step_index=len(step_results),
            total_steps=len(wf.steps),
            step_results=[s.to_dict() for s in step_results],
            final_output=accumulated_data,
            error=overall_error,
        )

