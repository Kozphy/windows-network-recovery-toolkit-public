"""Typed models for process classification (Step 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ProcessClassificationKind(StrEnum):
    """Represent process classification kind data used by the toolkit.
    
    Attributes:
        KNOWN_CURSOR_PROXY: Field or variant describing k n o w n c u r s o r p r o x y evidence or state.
        KNOWN_VSCODE_EXTENSION: Field or variant describing k n o w n v s c o d e e x t e n s i o n evidence or state.
        KNOWN_DEV_PROXY: Field or variant describing k n o w n d e v p r o x y evidence or state.
        KNOWN_SECURITY_TOOL: Field or variant describing k n o w n s e c u r i t y t o o l evidence or state.
        KNOWN_BROWSER_PROXY: Field or variant describing k n o w n b r o w s e r p r o x y evidence or state.
        UNKNOWN_LOCAL_PROXY: Field or variant describing u n k n o w n l o c a l p r o x y evidence or state.
        SUSPICIOUS_PROXY: Field or variant describing s u s p i c i o u s p r o x y evidence or state.
        POSSIBLE_MITM_RISK: Field or variant describing p o s s i b l e m i t m r i s k evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    KNOWN_CURSOR_PROXY = "KNOWN_CURSOR_PROXY"
    KNOWN_VSCODE_EXTENSION = "KNOWN_VSCODE_EXTENSION"
    KNOWN_DEV_PROXY = "KNOWN_DEV_PROXY"
    KNOWN_SECURITY_TOOL = "KNOWN_SECURITY_TOOL"
    KNOWN_BROWSER_PROXY = "KNOWN_BROWSER_PROXY"
    UNKNOWN_LOCAL_PROXY = "UNKNOWN_LOCAL_PROXY"
    SUSPICIOUS_PROXY = "SUSPICIOUS_PROXY"
    POSSIBLE_MITM_RISK = "POSSIBLE_MITM_RISK"
    REGISTRY_WRITER_CONFIRMED = "REGISTRY_WRITER_CONFIRMED"
    BENIGN_SYSTEM_CHANGE = "BENIGN_SYSTEM_CHANGE"
    CORRELATION_ONLY = "CORRELATION_ONLY"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProcessNode:
    """Represent process node data used by the toolkit.
    
    Attributes:
        process_guid: Field or variant describing process guid evidence or state.
        image_path: Field or variant describing image path evidence or state.
        process_name: Field or variant describing process name evidence or state.
        process_id: Field or variant describing process id evidence or state.
        command_line: Field or variant describing command line evidence or state.
        parent_process_guid: Field or variant describing parent process guid evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    process_guid: str | None = None
    image_path: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    command_line: str | None = None
    parent_process_guid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "process_guid": self.process_guid,
            "image_path": self.image_path,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "command_line": self.command_line,
            "parent_process_guid": self.parent_process_guid,
        }


@dataclass
class ProcessClassificationInput:
    """Represent process classification input data used by the toolkit.
    
    Attributes:
        image_path: Field or variant describing image path evidence or state.
        process_name: Field or variant describing process name evidence or state.
        process_guid: Field or variant describing process guid evidence or state.
        process_id: Field or variant describing process id evidence or state.
        command_line: Field or variant describing command line evidence or state.
        parent_image_path: Field or variant describing parent image path evidence or state.
        parent_process_name: Field or variant describing parent process name evidence or state.
        parent_command_line: Field or variant describing parent command line evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    image_path: str | None = None
    process_name: str | None = None
    process_guid: str | None = None
    process_id: int | None = None
    command_line: str | None = None
    parent_image_path: str | None = None
    parent_process_name: str | None = None
    parent_command_line: str | None = None
    ancestor_chain: list[ProcessNode] = field(default_factory=list)
    hashes: dict[str, str] | None = None
    signature_status: str | None = None
    user: str | None = None
    working_directory: str | None = None
    registry_target: str = ""
    registry_value_name: str = ""
    registry_details: str | None = None
    proxy_server_after: str | None = None
    localhost_port: int | None = None
    event_timestamp_utc: str = ""
    causation_level: str | None = None
    has_registry_writer_proof: bool = False
    has_listener_only: bool = False

    @classmethod
    def from_causation_dict(
        cls,
        causation: dict[str, Any],
        *,
        proxy_server: str | None = None,
        registry_value_name: str = "",
    ) -> ProcessClassificationInput:
        """From causation dict.
        
        Args:
            causation: The causation value supplied by the caller.
            proxy_server: The proxy server value supplied by the caller.
            registry_value_name: The registry value name value supplied by the caller.
        
        Returns:
            The ProcessClassificationInput result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        chain = [
            ProcessNode(
                process_guid=n.get("process_guid"),
                image_path=n.get("image"),
                process_name=(n.get("image") or "").split("\\")[-1] if n.get("image") else None,
                command_line=n.get("command_line"),
            )
            for n in (causation.get("process_tree") or [])
            if isinstance(n, dict)
        ]
        image = causation.get("writer_process")
        level = str(causation.get("causation_level") or "")
        return cls(
            image_path=image,
            process_name=(image or "").split("\\")[-1] if image else None,
            process_guid=causation.get("writer_process_guid"),
            process_id=causation.get("writer_pid"),
            command_line=causation.get("writer_command_line"),
            parent_image_path=causation.get("parent_process"),
            parent_process_name=(causation.get("parent_process") or "").split("\\")[-1]
            if causation.get("parent_process")
            else None,
            parent_command_line=causation.get("parent_command_line"),
            ancestor_chain=chain,
            hashes={"raw": causation.get("writer_hashes")} if causation.get("writer_hashes") else None,
            registry_target=str(causation.get("matched_registry_target") or ""),
            registry_value_name=registry_value_name,
            registry_details=causation.get("matched_registry_details"),
            proxy_server_after=proxy_server,
            localhost_port=causation.get("observed_localhost_port"),
            causation_level=level,
            has_registry_writer_proof=level in ("FINAL_CAUSATION", "STRONG_CAUSATION"),
            has_listener_only=level in ("CORRELATION_ONLY", "UNKNOWN"),
        )


@dataclass
class ProcessClassificationResult:
    """Represent process classification result data used by the toolkit.
    
    Attributes:
        classification: Field or variant describing classification evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        reasons: Field or variant describing reasons evidence or state.
        risk_factors: Field or variant describing risk factors evidence or state.
        trust_factors: Field or variant describing trust factors evidence or state.
        recommended_review: Field or variant describing recommended review evidence or state.
        summary: Field or variant describing summary evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    classification: ProcessClassificationKind
    confidence: float
    reasons: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    trust_factors: list[str] = field(default_factory=list)
    recommended_review: bool = False
    summary: str = ""

    @property
    def label(self) -> str:
        """Label.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self.classification.value

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "classification": self.classification.value,
            "label": self.classification.value,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "risk_factors": list(self.risk_factors),
            "trust_factors": list(self.trust_factors),
            "recommended_review": self.recommended_review,
            "summary": self.summary,
            "explanation": self.summary,
        }
