from pydantic import BaseModel
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceScore(BaseModel):
    classification: str
    confidence: float  # 0-100
    alternative: Optional[str] = None
    alternative_confidence: Optional[float] = None


class EventType(str, Enum):
    FORCED_ENTRY = "forced_entry"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PANIC_CALL = "panic_call"
    GUNSHOT_AUDIO = "gunshot_audio"
    DOOR_CONTACT = "door_contact"
    MOTION_DETECTION = "motion_detection"
    AFTER_HOURS_ACCESS = "after_hours_access"
    CAMERA_OBSTRUCTION = "camera_obstruction"
    LOITERING = "loitering"
    FAILED_BADGE = "failed_badge"
    # ADD THESE:
    EXPLOSION = "explosion"
    FIRE = "fire"
    ARSON = "arson"
    SMOKE = "smoke"


class Signal(BaseModel):
    type: EventType
    confidence: float  # 0-100
    timestamp: datetime
    location: str
    metadata: Dict[str, Any] = {}


class SecurityContext(BaseModel):
    zone_type: str  # "high_security", "low_security", "blind_spot"
    time_of_day: str
    authorized_personnel: List[str]
    expected_behavior: Optional[str] = None
    metadata: Dict[str, Any] = {}


class Recommendation(BaseModel):
    action: str
    urgency: str  # "immediate", "soon", "monitor"
    requires_human_approval: bool = False
    confidence: ConfidenceScore
    reasoning: str
    visual_cue: str  # "🔴 RED", "🟡 YELLOW", "🟢 GREEN"


class IncidentReport(BaseModel):
    incident_id: str
    threat_level: ThreatLevel
    confidence: float
    signals_analyzed: List[Signal]
    timeline: List[Dict]
    recommendation: Recommendation
    requires_human_review: bool = False
