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
    name="Sync Clipboard & Notify",
    description="Synchronize Windows clipboard text to the connected Android phone and record a redacted completion event.",
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
            step_id="step_push_to_phone",
            capability="android_clipboard_push",
            name="Push Clipboard to Phone",
            description="Transfer the clipboard text directly to the connected Android phone.",
            target_device="android",
            is_mutating=True,
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
    is_mutating=True,
    requires_approval=False,
    max_timeout_seconds=25.0,
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

PRESET_STUDY_MODE = WorkflowDefinition(
    workflow_id="study_mode",
    name="Study Mode",
    description="Enable distraction-free focus: optionally enable phone DND when permitted, adjust Windows volume down cleanly, and post a desktop summary notification.",
    steps=[
        WorkflowStep(
            step_id="step_phone_dnd",
            capability="android_dnd_toggle",
            name="Enable Phone Do Not Disturb",
            description="Request Do Not Disturb mode on the connected Android phone if permitted.",
            params_template={"enabled": True},
            target_device="android",
            is_mutating=True,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_desktop_volume",
            capability="media_control",
            name="Quiet Windows Volume",
            description="Lower Windows master volume to a distraction-free study level.",
            params_template={"action": "volume_set", "value": 15},
            is_mutating=True,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_study_notify",
            capability="windows_notify",
            name="Notify Study Mode Active",
            description="Post a confirmation toast on Windows.",
            params_template={"title": "SNOW Study Mode", "message": "Study Mode active."},
            is_mutating=False,
            requires_approval=False,
        ),
    ],
    is_mutating=True,
    requires_approval=False,
    max_timeout_seconds=25.0,
)

PRESET_FIND_AND_SEND_FILE = WorkflowDefinition(
    workflow_id="find_and_send_file",
    name="Find & Send File to Phone",
    description="Search allowed Windows roots for a matching file query and transfer the first match securely over HTTPS to Android.",
    steps=[
        WorkflowStep(
            step_id="step_find_file",
            capability="windows_file_search",
            name="Search Allowed PC Files",
            description="Search scoped PC roots for the requested file query.",
            params_template={"limit": 5},
            is_mutating=False,
            requires_approval=False,
        ),
        WorkflowStep(
            step_id="step_deliver_to_phone",
            capability="android_file_send",
            name="Deliver File to Phone",
            description="Deliver the matched PC file securely over HTTPS to the connected Android phone.",
            target_device="android",
            is_mutating=True,
            requires_approval=True,
        ),
    ],
    is_mutating=True,
    requires_approval=True,
    max_timeout_seconds=45.0,
)

PRESET_CAPTURE_AND_SHARE = WorkflowDefinition(
    workflow_id="capture_and_share",
    name="Capture & Share Screenshot",
    description="Capture the Windows desktop screenshot with consent and share/deliver it to the connected Android device.",
    steps=[
        WorkflowStep(
            step_id="step_capture_screen",
            capability="windows_screenshot",
            name="Capture Windows Screen",
            description="Acquire desktop screen capture as an encoded PNG.",
            is_mutating=False,
            requires_approval=True,
        ),
        WorkflowStep(
            step_id="step_deliver_to_phone",
            capability="android_file_send",
            name="Send Capture to Phone",
            description="Deliver the captured PNG over HTTPS to the connected Android device.",
            target_device="android",
            is_mutating=True,
            requires_approval=True,
        ),
    ],
    is_mutating=True,
    requires_approval=True,
    max_timeout_seconds=45.0,
)

# Immutable fixed registry of allowable workflows
WORKFLOW_REGISTRY: dict[str, WorkflowDefinition] = {
    PRESET_DEVICE_HEALTH.workflow_id: PRESET_DEVICE_HEALTH,
    PRESET_CAPTURE_PC_TO_PHONE.workflow_id: PRESET_CAPTURE_PC_TO_PHONE,
    PRESET_SHARE_CLIPBOARD.workflow_id: PRESET_SHARE_CLIPBOARD,
    PRESET_PC_SCREENSHOT.workflow_id: PRESET_PC_SCREENSHOT,
    PRESET_STUDY_MODE.workflow_id: PRESET_STUDY_MODE,
    PRESET_FIND_AND_SEND_FILE.workflow_id: PRESET_FIND_AND_SEND_FILE,
    PRESET_CAPTURE_AND_SHARE.workflow_id: PRESET_CAPTURE_AND_SHARE,
}


class WorkflowOrchestrator:
    """Declarative workflow execution engine delegating all actions to CapabilityEngine."""

    def __init__(self, capability_engine: Any) -> None:
        self.capability_engine = capability_engine

    def _find_connected_android_node(self) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Find an active connected Android node, returning (device_id, device_name, transport)."""
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
                    is_conn = getattr(n, "is_connected", False)
                    reach = getattr(n, "reachability", None) or getattr(n, "reachability_state", None)
                    st_val = str(getattr(reach, "value", reach) or "").upper()
                    if is_conn or any(k in st_val for k in ("ONLINE", "REACHABLE", "CONNECTED")):
                        trans = getattr(n, "transport", None) or getattr(n, "transport_type", None) or "USB ADB / Wi-Fi LAN"
                        dev_name = getattr(n, "device_name", None) or n.device_id
                        return (n.device_id, dev_name, str(trans))

            # Pass 2: any android node
            for n in nodes:
                if _is_android(n):
                    trans = getattr(n, "transport", None) or getattr(n, "transport_type", None) or "Offline"
                    dev_name = getattr(n, "device_name", None) or n.device_id
                    return (n.device_id, dev_name, str(trans))

        return (None, None, None)

    def _find_connected_android_device_id(self) -> Optional[str]:
        """Find an active connected Android node from NodeRegistry or SessionRouter."""
        dev_id, _, _ = self._find_connected_android_node()
        return dev_id

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
        workflow_approved: bool = False,
    ) -> WorkflowExecutionReport:
        """Execute a declared workflow in sequential steps through CapabilityEngine.

        Args:
            workflow_id: Registered preset identifier.
            params: Optional caller arguments mapped to steps.
            ctx: ExecutionContext (derives caller principal, e.g. OWNER_MANUAL or AI_MCP).
            workflow_approved: Trusted flag from CapabilityEngine indicating that human owner
                               approval for this workflow was verified and consumed.

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
        raw_clipboard_text: str = ""

        input_params = dict(params or {})
        # Strip spoofable security keys
        input_params.pop("principal", None)
        input_params.pop("trust_tier", None)
        input_params.pop("execution_principal", None)

        # Security Policy: A caller-supplied approval_id in input_params NEVER independently grants
        # OWNER_MANUAL privileges. Privileges are ONLY promoted to OWNER_MANUAL if the caller is
        # already OWNER_MANUAL or if CapabilityEngine verified and consumed an authentic owner approval
        # token (workflow_approved=True).
        is_owner_authorized = (
            effective_ctx.principal == ExecutionPrincipal.OWNER_MANUAL
            or workflow_approved is True
        )
        step_execution_ctx = (
            ExecutionContext(
                principal=ExecutionPrincipal.OWNER_MANUAL,
                origin=f"workflow:{workflow_id}",
                device_id=effective_ctx.device_id,
            )
            if is_owner_authorized
            else effective_ctx
        )

        for idx, step in enumerate(wf.steps):
            step_order = idx + 1
            step_start_mono = time.monotonic()
            step_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Merge step template with validated parameters
            step_params = dict(step.params_template)
            if step.step_id == "step_find_file":
                if "query" in input_params:
                    step_params["query"] = str(input_params["query"])
                if "root_path" in input_params:
                    step_params["root_path"] = str(input_params["root_path"])
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
            elif step.step_id == "step_deliver_to_phone" and "step_find_file" in accumulated_data:
                find_data = accumulated_data["step_find_file"]
                matches = find_data.get("matches") if isinstance(find_data, dict) else None
                if isinstance(matches, list) and matches:
                    first_match = matches[0]
                    if isinstance(first_match, dict):
                        fp = first_match.get("full_path") or first_match.get("path")
                        if fp:
                            step_params["file_path"] = fp
                        if first_match.get("name"):
                            step_params["file_name"] = first_match["name"]
                elif "file_path" in input_params:
                    step_params["file_path"] = input_params["file_path"]

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

            # Handle clipboard push step specifically
            if step.step_id == "step_push_to_phone":
                actual_android_id, actual_android_name, _ = self._find_connected_android_node()
                if not raw_clipboard_text or len(raw_clipboard_text.strip()) == 0:
                    # Clipboard is empty: record clean empty summary without failing
                    step_finish_mono = time.monotonic()
                    step_finish_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    empty_data = {
                        "status": "EMPTY",
                        "synced_chars": 0,
                        "is_empty": True,
                        "message": "Clipboard is empty; no text to synchronize.",
                        "device_name": actual_android_name or "Android Phone",
                    }
                    accumulated_data[step.step_id] = empty_data
                    accumulated_data["sync_summary"] = empty_data
                    step_results.append(
                        WorkflowStepResult(
                            step_id=step.step_id,
                            order=step_order,
                            capability=step.capability,
                            name=step.name,
                            status="SUCCESS",
                            start_time=step_start_iso,
                            finish_time=step_finish_iso,
                            duration_seconds=step_finish_mono - step_start_mono,
                            data=empty_data,
                        )
                    )
                    continue

                if not actual_android_id:
                    # Non-empty clipboard but peer is offline: report partial failure honestly
                    step_finish_mono = time.monotonic()
                    step_finish_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    offline_data = {"status": "DEVICE_OFFLINE", "synced_chars": 0, "is_empty": False}
                    step_results.append(
                        WorkflowStepResult(
                            step_id=step.step_id,
                            order=step_order,
                            capability=step.capability,
                            name=step.name,
                            status="FAILED",
                            start_time=step_start_iso,
                            finish_time=step_finish_iso,
                            duration_seconds=step_finish_mono - step_start_mono,
                            data=offline_data,
                            error="Connected Android phone is offline or unreachable.",
                        )
                    )
                    overall_status = "PARTIAL"
                    overall_error = "Connected Android phone is offline or unreachable; clipboard could not be synchronized."
                    break

                target_dev = actual_android_id
                step_params["target"] = actual_android_id
                step_params["text"] = raw_clipboard_text
            elif target_dev == "android":
                # Resolve dynamic Android target device ID when available
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
                resp: CapabilityResponse = await self.capability_engine.execute(req, ctx=step_execution_ctx)
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
                is_optional_peer_step = step.step_id in (
                    "step_phone_battery",
                    "step_deliver_to_phone",
                    "step_phone_dnd",
                ) and resp.status in (
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
                # Capture raw clipboard text safely before redacting report output
                if step.step_id == "step_read_clipboard":
                    raw_clipboard_text = str((resp.data or {}).get("text", "") or "")
                # Prevent leaking raw clipboard text
                if "text" in clean_data and (step.capability.startswith("windows_clipboard") or "clipboard" in step.capability):
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

        # Build consumer-friendly workflow summary metadata
        actual_id, actual_name, actual_trans = self._find_connected_android_node()
        if wf.workflow_id == "device_health_snapshot":
            win_data = accumulated_data.get("step_windows_telemetry", {})
            cpu_obj = win_data.get("cpu") if isinstance(win_data.get("cpu"), dict) else {}
            mem_obj = win_data.get("memory") if isinstance(win_data.get("memory"), dict) else {}
            disk_obj = win_data.get("disk") if isinstance(win_data.get("disk"), dict) else {}

            cpu_pct = cpu_obj.get("utilization_percent") if cpu_obj.get("utilization_percent") is not None else win_data.get("cpu_percent")
            ram_used = mem_obj.get("used_mb") if mem_obj.get("used_mb") is not None else (
                round(win_data["ram_used_bytes"] / (1024 * 1024), 2) if "ram_used_bytes" in win_data else None
            )
            ram_total = mem_obj.get("total_mb") if mem_obj.get("total_mb") is not None else (
                round(win_data["ram_total_bytes"] / (1024 * 1024), 2) if "ram_total_bytes" in win_data else None
            )
            ram_pct = mem_obj.get("percent") if mem_obj.get("percent") is not None else win_data.get("ram_percent")
            disk_pct = disk_obj.get("percent") if disk_obj.get("percent") is not None else win_data.get("disk_c_percent")

            phone_battery = accumulated_data.get("step_phone_battery", {})
            accumulated_data["health_summary"] = {
                "windows": {
                    "hostname": win_data.get("hostname") or win_data.get("node_name") or "Windows Laptop",
                    "cpu_percent": cpu_pct,
                    "ram_used_mb": ram_used,
                    "ram_total_mb": ram_total,
                    "ram_percent": ram_pct,
                    "disk_percent": disk_pct,
                },
                "phone": {
                    "device_name": actual_name or "Android Phone",
                    "battery_percent": phone_battery.get("battery_level") or phone_battery.get("battery_percent") or phone_battery.get("level"),
                    "charging": phone_battery.get("is_charging") or phone_battery.get("charging"),
                    "transport": actual_trans or "USB ADB / Wi-Fi LAN",
                    "ram_total_bytes": phone_battery.get("ram_total_bytes"),
                    "ram_available_bytes": phone_battery.get("ram_available_bytes"),
                    "storage_total_bytes": phone_battery.get("storage_total_bytes"),
                    "storage_available_bytes": phone_battery.get("storage_available_bytes"),
                    "is_online": actual_id is not None and "step_phone_battery" in accumulated_data,
                },
            }
        elif wf.workflow_id == "pc_screenshot":
            cap_data = accumulated_data.get("step_pc_screenshot") or accumulated_data.get("step_capture_screen", {})
            w = cap_data.get("width")
            h = cap_data.get("height")
            dims = f"{w} × {h}" if (w is not None and h is not None) else (cap_data.get("dimensions") or cap_data.get("resolution"))
            accumulated_data["capture_summary"] = {
                "dimensions": dims,
                "file_size_bytes": cap_data.get("size_bytes") if cap_data.get("size_bytes") is not None else cap_data.get("file_size_bytes"),
                "file_name": cap_data.get("file_name"),
                "captured_at": cap_data.get("captured_at") or finish_time_iso,
            }
        elif wf.workflow_id == "capture_pc_to_phone":
            cap_data = accumulated_data.get("step_pc_screenshot") or accumulated_data.get("step_capture_screen", {})
            del_data = accumulated_data.get("step_deliver_to_phone", {})
            w = cap_data.get("width")
            h = cap_data.get("height")
            dims = f"{w} × {h}" if (w is not None and h is not None) else (cap_data.get("dimensions") or cap_data.get("resolution"))
            accumulated_data["delivery_summary"] = {
                "dimensions": dims,
                "file_size_bytes": cap_data.get("size_bytes") if cap_data.get("size_bytes") is not None else cap_data.get("file_size_bytes"),
                "file_name": cap_data.get("file_name"),
                "destination_device": actual_name or "realme RMX5110",
                "transfer_status": del_data.get("status") or "SUCCESS",
                "duration_seconds": del_data.get("duration_seconds"),
            }
        elif wf.workflow_id == "share_clipboard_and_notify":
            if "sync_summary" not in accumulated_data:
                push_res = accumulated_data.get("step_push_to_phone", {})
                synced_chars = len(raw_clipboard_text) if raw_clipboard_text else 0
                accumulated_data["sync_summary"] = {
                    "synced_chars": synced_chars,
                    "is_empty": not bool(raw_clipboard_text),
                    "device_name": actual_name or "realme RMX5110",
                    "status": "SUCCESS" if raw_clipboard_text else "EMPTY",
                }

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

