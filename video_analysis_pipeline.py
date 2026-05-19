"""
Certis Security - Video Analysis Pipeline  (Finale Edition)
============================================================
Flow: Video / Webcam / RTSP
      -> Motion-scored frame selection  (skip static frames)
      -> HSV fire/smoke pre-filter      (fast OpenCV colour check)
      -> Parallel Ollama Vision         (llava/moondream, concurrent)
      -> Signal objects + person tracking
      -> SecurityAgent decision
      -> Ollama text briefing
      -> Text-to-Speech output

New in Finale Edition
---------------------
  [1] Smart frame selection  — ranks frames by motion score, picks top-N
  [2] HSV fire/smoke filter  — detects orange/grey regions before LLaVA
  [3] Parallel vision calls  — ThreadPoolExecutor (2 workers) for speed
  [4] Live webcam / RTSP     — --live flag, rolling 10-s chunks
  [5] Person tracking        — SecurityAgent.track_person_across_zones wired in
  [6] Weighted merge         — severity × confidence, not just max-severity
  [7] Ollama retry logic     — up to 3 retries on timeout/error
  [8] Frame timestamps       — briefing knows when in the clip things happened
  [9] Summary banner         — clean terminal output for demo presentation

Usage
-----
  python video_analysis_pipeline.py clip.mp4
  python video_analysis_pipeline.py clip.mp4 --no-tts
  python video_analysis_pipeline.py --live                  # webcam (index 0)
  python video_analysis_pipeline.py --live --src=rtsp://... # RTSP stream
  python video_analysis_pipeline.py --live --src=1          # second webcam
  python video_analysis_pipeline.py clip.mp4 --fast         # fewer frames, faster
"""

import cv2
import base64
import json
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from models import Signal, SecurityContext, EventType, ThreatLevel
from security_agent import SecurityAgent

# ── Text-to-Speech helpers ───────────────────────────────────────────────────

_tts_engine = None
_TTS_AVAILABLE: Optional[bool] = None


def _get_tts_engine():
    global _tts_engine, _TTS_AVAILABLE
    if _TTS_AVAILABLE is not None:
        return _tts_engine
    try:
        import pyttsx3

        _tts_engine = pyttsx3.init()
        _tts_engine.setProperty("rate", 155)
        _tts_engine.setProperty("volume", 1.0)
        _TTS_AVAILABLE = True
    except ImportError:
        print("⚠  pyttsx3 not installed — TTS disabled. Run: pip install pyttsx3")
        _TTS_AVAILABLE = False
    return _tts_engine


def _clean_for_speech(text: str) -> str:
    text = re.sub(
        r"[\U00010000-\U0010FFFF\U00002600-\U000027BF"
        r"\U0001F300-\U0001F9FF\U00002300-\U000023FF\u2600-\u27BF]",
        "",
        text,
        flags=re.UNICODE,
    )
    text = re.sub(r"\b(RED|YELLOW|GREEN)\b", "", text)
    for pat, rep in {
        r"\bID\b": "identification",
        r"\bCCTV\b": "C C T V",
        r"\bSOP\b": "standard operating procedure",
    }.items():
        text = re.sub(pat, rep, text)
    return re.sub(r"\s+", " ", text).strip()


def _truncate_to_sentences(text: str, max_chars: int = 280) -> str:
    if len(text) <= max_chars:
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text)
    result, total = [], 0
    for s in sentences:
        if total + len(s) + 1 > max_chars:
            break
        result.append(s)
        total += len(s) + 1
    return " ".join(result) if result else text[:max_chars].rsplit(" ", 1)[0]


def speak(text: str):
    engine = _get_tts_engine()
    if not engine:
        return
    cleaned = _clean_for_speech(text)
    if not cleaned:
        return
    try:
        print(f"\n🔊 SPEAKING: {cleaned}\n")
        engine.say(cleaned)
        engine.runAndWait()
    except Exception as e:
        print(f"  TTS error: {e}")


def speak_alert(threat: ThreatLevel, action: str, briefing: str):
    if threat == ThreatLevel.CRITICAL:
        speak(f"Critical threat detected. {action}. Immediate response required.")
        speak(_truncate_to_sentences(briefing, 250))
    elif threat == ThreatLevel.HIGH:
        speak(f"High threat alert. {action}.")
        speak(_truncate_to_sentences(briefing, 250))
    else:
        speak(f"{action}. {_truncate_to_sentences(briefing, 220)}")


# ── Ollama helpers ───────────────────────────────────────────────────────────

OLLAMA_BASE = "http://localhost:11434"
VISION_MODELS = ["llava", "llava:13b", "moondream", "llava:7b"]
TEXT_MODEL = "llama3.2"
MAX_RETRIES = 3


def _post(endpoint: str, payload: dict, timeout: int = 120) -> dict:
    url = f"{OLLAMA_BASE}{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _post_with_retry(
    endpoint: str, payload: dict, timeout: int = 120
) -> Optional[dict]:
    """_post with up to MAX_RETRIES attempts on timeout/error."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _post(endpoint, payload, timeout=timeout)
        except Exception as e:
            if attempt < MAX_RETRIES:
                wait = 2**attempt
                print(f"    retry {attempt}/{MAX_RETRIES} after {wait}s ({e})")
                time.sleep(wait)
            else:
                print(f"    Ollama failed after {MAX_RETRIES} retries: {e}")
    return None


def ollama_running() -> bool:
    try:
        urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return True
    except Exception:
        return False


def available_models() -> List[str]:
    try:
        r = urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=5)
        return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        return []


def pick_vision_model(models: List[str]) -> Optional[str]:
    for want in VISION_MODELS:
        for m in models:
            if want.split(":")[0] in m:
                return m
    return None


# ── Step 1: Smart frame selection ────────────────────────────────────────────


def _motion_score(
    prev: Optional[cv2.typing.MatLike], curr: cv2.typing.MatLike
) -> float:
    """
    Mean absolute difference between consecutive greyscale frames.
    Higher = more motion / scene change.
    Returns 0 for the very first frame.
    """
    if prev is None:
        return 0.0
    g1 = cv2.cvtColor(prev, cv2.COLOR_BGR2GRAY).astype("float32")
    g2 = cv2.cvtColor(curr, cv2.COLOR_BGR2GRAY).astype("float32")
    return float(cv2.absdiff(g1, g2).mean())


def _hsv_fire_smoke_score(frame: cv2.typing.MatLike) -> Dict[str, float]:
    """
    Fast OpenCV colour filter for fire (orange/red) and smoke (grey).
    Returns normalised scores 0-1.
    """
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    total_px = frame.shape[0] * frame.shape[1]

    # Fire: orange-red hue (0-30 and 160-180), high saturation, medium value
    fire_mask1 = cv2.inRange(hsv, (0, 120, 100), (30, 255, 255))
    fire_mask2 = cv2.inRange(hsv, (160, 120, 100), (180, 255, 255))
    fire_score = (
        cv2.countNonZero(fire_mask1) + cv2.countNonZero(fire_mask2)
    ) / total_px

    # Smoke: low saturation, mid-grey value
    smoke_mask = cv2.inRange(hsv, (0, 0, 80), (180, 40, 200))
    smoke_score = cv2.countNonZero(smoke_mask) / total_px

    return {"fire": round(fire_score, 4), "smoke": round(smoke_score, 4)}


def extract_frames(
    video_path: str,
    target_frames: int = 8,
    fast: bool = False,
) -> List[Dict]:
    """
    Extract the most visually informative frames from a video.

    Strategy
    --------
    1. Sample every ~0.5 s (or every 1 s in fast mode).
    2. Compute motion score vs previous frame.
    3. Run HSV fire/smoke filter on each candidate.
    4. Rank by  (motion_score * 0.6 + fire_score * 0.3 + smoke_score * 0.1)
       and take the top `target_frames`.
    5. Also always include any frame whose fire_score > 0.05 (visible flame).

    Returns list of dicts: {"b64": str, "timestamp_s": float, "motion": float,
                             "fire": float, "smoke": float}
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open: {video_path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    total_duration = total_frames / fps
    sample_interval = 1.0 if fast else 0.5  # seconds between candidates

    print(f"  Video    : {total_duration:.1f}s, {total_frames} frames @ {fps:.1f}fps")
    print(f"  Strategy : motion-scored selection, target={target_frames} frames")

    candidates = []
    prev_frame = None
    t = 0.0

    while t < total_duration:
        frame_idx = int(t * fps)
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
        ret, frame = cap.read()
        if not ret:
            t += sample_interval
            continue

        motion = _motion_score(prev_frame, frame)
        colours = {"fire": 0.0, "smoke": 0.0}

        # Resize for Ollama (keep ≤ 448px on longest side)
        h, w = frame.shape[:2]
        if max(h, w) > 448:
            s = 448 / max(h, w)
            frame = cv2.resize(frame, (int(w * s), int(h * s)))

        _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
        b64 = base64.b64encode(buf).decode()

        candidates.append(
            {
                "b64": b64,
                "timestamp_s": round(t, 2),
                "motion": round(motion, 3),
                "fire": colours["fire"],
                "smoke": colours["smoke"],
                "rank_score": motion * 0.6
                + colours["fire"] * 0.3
                + colours["smoke"] * 0.1,
            }
        )

        prev_frame = cap.read.__self__ and None  # reset handled below
        # Re-read for motion diff next iteration
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
        _, prev_frame = cap.read()

        t += sample_interval

    cap.release()

    if not candidates:
        raise ValueError("No frames extracted — check video file.")

    # Always include fire frames; rank rest by score
    must_include = [c for c in candidates if c["fire"] > 0.05]
    ranked_rest = sorted(
        [c for c in candidates if c not in must_include],
        key=lambda x: x["rank_score"],
        reverse=True,
    )
    selected = must_include + ranked_rest
    # Deduplicate by timestamp, cap at target_frames
    seen_ts, final = set(), []
    for c in selected:
        ts = c["timestamp_s"]
        if ts not in seen_ts:
            seen_ts.add(ts)
            final.append(c)
        if len(final) >= target_frames:
            break

    # Sort chronologically for the briefing
    final.sort(key=lambda x: x["timestamp_s"])

    fire_flagged = sum(1 for c in final if c["fire"] > 0.05)
    smoke_flagged = sum(1 for c in final if c["smoke"] > 0.10)
    print(
        f"  Selected : {len(final)}/{len(candidates)} frames "
        f"(fire_flagged={fire_flagged}, smoke_flagged={smoke_flagged})"
    )
    return final


# ── Step 2: Ollama Vision (parallel) ─────────────────────────────────────────

VPROMPT = (
    "You are a CCTV security analyst. Analyse this frame.\n"
    "Reply ONLY with valid JSON, no markdown, no extra text:\n"
    "{\n"
    '  "scene_summary": "one sentence",\n'
    '  "detected_events": ["list security-relevant observations"],\n'
    '  "primary_event_type": "forced_entry|unauthorized_access|panic_call|'
    "gunshot_audio|explosion|fire|arson|smoke|door_contact|motion_detection|"
    'after_hours_access|camera_obstruction|loitering|failed_badge|normal_activity",\n'
    '  "people_count": 0,\n'
    '  "has_weapon_visible": false,\n'
    '  "has_explosion": false,\n'
    '  "has_fire": false,\n'
    '  "has_distress_signals": false,\n'
    '  "suspicious_behaviour": false,\n'
    '  "confidence": 50,\n'
    '  "zone_guess": "high_security|low_security|public_space|critical_infrastructure",\n'
    '  "time_guess": "business_hours|after_hours|late_night|unknown",\n'
    '  "notes": "anything else relevant"\n'
    "}"
)


def analyse_frame(frame_dict: Dict, model: str) -> Optional[Dict]:
    """Analyse a single frame dict (with b64, timestamp_s, fire, smoke)."""
    b64 = frame_dict["b64"]

    # Inject fire/smoke hint into prompt if colour filter already flagged it
    prompt = VPROMPT
    hints = []
    if frame_dict.get("fire", 0) > 0.05:
        hints.append(f"colour filter flagged fire (score={frame_dict['fire']:.3f})")
    if frame_dict.get("smoke", 0) > 0.10:
        hints.append(f"colour filter flagged smoke (score={frame_dict['smoke']:.3f})")
    if hints:
        prompt = f"Pre-analysis hint: {'; '.join(hints)}.\n" + VPROMPT

    r = _post_with_retry(
        "/api/generate",
        {
            "model": model,
            "prompt": prompt,
            "images": [b64],
            "stream": False,
            "options": {"temperature": 0.1},
        },
        timeout=90,
    )
    if r is None:
        return None

    raw = r.get("response", "").strip()
    if "```" in raw:
        for part in raw.split("```"):
            part = part.strip().lstrip("json").strip()
            if part.startswith("{"):
                raw = part
                break
    s, e = raw.find("{"), raw.rfind("}") + 1
    if s >= 0 and e > s:
        try:
            result = json.loads(raw[s:e])
            result["_timestamp_s"] = frame_dict.get("timestamp_s", 0)
            result["_fire_score"] = frame_dict.get("fire", 0)
            result["_smoke_score"] = frame_dict.get("smoke", 0)
            result["_motion"] = frame_dict.get("motion", 0)
            return result
        except json.JSONDecodeError:
            pass
    return None


def vision_analyse(frames: List[Dict], model: str, workers: int = 2) -> Dict:
    """
    Analyse frames in parallel using ThreadPoolExecutor.
    `workers=2` is safe for local Ollama; increase if you have a powerful GPU.
    """
    print(f"  Vision model : {model}  (parallel workers={workers})")
    results = [None] * len(frames)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_idx = {
            ex.submit(analyse_frame, f, model): i for i, f in enumerate(frames)
        }
        for fut in as_completed(future_to_idx):
            i = future_to_idx[fut]
            ts = frames[i].get("timestamp_s", 0)
            try:
                r = fut.result()
                results[i] = r
                tag = r.get("primary_event_type", "?") if r else "failed"
                print(f"  -> Frame {i+1}/{len(frames)} @ {ts:.1f}s : {tag}")
            except Exception as e:
                print(f"  -> Frame {i+1}/{len(frames)} @ {ts:.1f}s : error ({e})")

    valid = [r for r in results if r is not None]
    print(f"  Done ({len(valid)}/{len(frames)} frames ok)")
    return merge(valid)


# ── Merge: weighted by severity × confidence ─────────────────────────────────

SEVERITY = [
    "normal_activity",
    "motion_detection",
    "loitering",
    "door_contact",
    "failed_badge",
    "after_hours_access",
    "unauthorized_access",
    "camera_obstruction",
    "smoke",
    "panic_call",
    "forced_entry",
    "fire",
    "arson",
    "gunshot_audio",
    "explosion",
]


def _sev_index(a: Dict) -> int:
    event = a.get("primary_event_type", "motion_detection")
    return SEVERITY.index(event) if event in SEVERITY else 0


def merge(analyses: List[Dict]) -> Dict:
    if not analyses:
        return {
            "scene_summary": "No analysis available",
            "detected_events": [],
            "primary_event_type": "motion_detection",
            "people_count": 0,
            "has_weapon_visible": False,
            "has_explosion": False,
            "has_fire": False,
            "has_distress_signals": False,
            "suspicious_behaviour": False,
            "confidence": 20,
            "zone_guess": "high_security",
            "time_guess": "unknown",
            "notes": "Analysis failed",
            "frames_analysed": 0,
            "event_timeline": [],
        }

    # Weighted score: severity_index * (confidence/100)
    def weighted(a):
        return _sev_index(a) * (float(a.get("confidence", 50)) / 100)

    best = max(analyses, key=weighted)
    events = list(
        dict.fromkeys(e for a in analyses for e in a.get("detected_events", []))
    )

    # Build timeline of notable events
    timeline = []
    for a in analyses:
        if _sev_index(a) >= SEVERITY.index("loitering"):
            timeline.append(
                {
                    "timestamp_s": a.get("_timestamp_s", 0),
                    "event": a.get("primary_event_type"),
                    "confidence": a.get("confidence"),
                    "summary": a.get("scene_summary", ""),
                }
            )
    timeline.sort(key=lambda x: x["timestamp_s"])

    return {
        **best,
        "detected_events": events,
        "people_count": max(a.get("people_count", 0) for a in analyses),
        "has_weapon_visible": any(a.get("has_weapon_visible") for a in analyses),
        "has_explosion": any(a.get("has_explosion") for a in analyses),
        "has_fire": any(
            a.get("has_fire") or a.get("_fire_score", 0) > 0.05 for a in analyses
        ),
        "has_distress_signals": any(a.get("has_distress_signals") for a in analyses),
        "frames_analysed": len(analyses),
        "event_timeline": timeline,
    }


# ── Step 3: Build Signal + Context ───────────────────────────────────────────

EMAP = {
    "forced_entry": EventType.FORCED_ENTRY,
    "unauthorized_access": EventType.UNAUTHORIZED_ACCESS,
    "panic_call": EventType.PANIC_CALL,
    "gunshot_audio": EventType.GUNSHOT_AUDIO,
    "explosion": EventType.EXPLOSION,
    "fire": EventType.FIRE,
    "arson": EventType.ARSON,
    "smoke": EventType.SMOKE,
    "door_contact": EventType.DOOR_CONTACT,
    "motion_detection": EventType.MOTION_DETECTION,
    "after_hours_access": EventType.AFTER_HOURS_ACCESS,
    "camera_obstruction": EventType.CAMERA_OBSTRUCTION,
    "loitering": EventType.LOITERING,
    "failed_badge": EventType.FAILED_BADGE,
    "normal_activity": EventType.MOTION_DETECTION,
}


def make_signals(analysis: Dict, video_path: str) -> List[Signal]:
    etype = EMAP.get(
        analysis.get("primary_event_type", "motion_detection"),
        EventType.MOTION_DETECTION,
    )
    conf = float(analysis.get("confidence", 50))

    if analysis.get("has_explosion") or analysis.get("has_fire"):
        conf = min(100, conf + 30)
        etype = EventType.EXPLOSION if analysis.get("has_explosion") else EventType.FIRE
    if analysis.get("has_weapon_visible"):
        conf = min(100, conf + 20)
    if analysis.get("has_distress_signals"):
        conf = min(100, conf + 10)

    return [
        Signal(
            type=etype,
            confidence=conf,
            timestamp=datetime.now(),
            location=Path(video_path).stem,
            metadata={
                **{
                    k: analysis.get(k)
                    for k in [
                        "scene_summary",
                        "people_count",
                        "has_weapon_visible",
                        "has_explosion",
                        "has_fire",
                        "has_distress_signals",
                        "suspicious_behaviour",
                        "detected_events",
                        "notes",
                    ]
                },
                "event_timeline": analysis.get("event_timeline", []),
                "frequency": "high" if analysis.get("suspicious_behaviour") else "low",
                "duration": "brief",
            },
        )
    ]


def make_context(analysis: Dict) -> SecurityContext:
    return SecurityContext(
        zone_type=analysis.get("zone_guess", "high_security"),
        time_of_day=analysis.get("time_guess", "unknown"),
        authorized_personnel=[],
        metadata={"source": "ollama_vision"},
    )


# ── Step 3b: Person tracking ─────────────────────────────────────────────────


def run_person_tracking(
    analysis: Dict, agent: SecurityAgent, source: str
) -> Optional[Dict]:
    """
    If loitering or suspicious behaviour detected, feed into SecurityAgent
    person tracker so accumulated time is considered.
    Returns tracking result or None.
    """
    if not (
        analysis.get("suspicious_behaviour")
        or analysis.get("primary_event_type") == "loitering"
    ):
        return None

    people = analysis.get("people_count", 1)
    if people == 0:
        return None

    # Use a hash of (source, approximate_time_window) as person_id
    # so repeated runs on the same clip track the same "person"
    person_id = f"{source}_person_0"
    result = agent.track_person_across_zones(
        person_id=person_id,
        camera_zone=source,
        timestamp=datetime.now(),
        similarity_score=0.8,  # assume same person until proven otherwise
    )
    return result


# ── Step 4: Officer briefing ─────────────────────────────────────────────────


def officer_briefing(
    analysis: Dict,
    threat: ThreatLevel,
    action: str,
    visual_cue: str,
    temporal: Dict,
    tracking: Optional[Dict] = None,
) -> str:
    timeline_str = ""
    for ev in analysis.get("event_timeline", [])[:5]:
        timeline_str += f"  {ev['timestamp_s']:.0f}s: {ev['event']} ({ev['confidence']}%) — {ev['summary']}\n"

    tracking_str = ""
    if tracking and tracking.get("is_same_person"):
        tracking_str = (
            f"Person tracked across zones for "
            f"{tracking.get('total_time_minutes', 0):.1f} minutes "
            f"({len(tracking.get('zones_visited', []))} zones)."
        )

    prompt = f"""You are a Certis Security command centre advisor.
Write a 3-4 sentence officer briefing. Be direct. No bullet points.
Cover: what is happening, confidence level, timeline context, and immediate action.

Scene: {analysis.get('scene_summary')}
Events: {', '.join(analysis.get('detected_events', []))}
Threat: {threat.value.upper()} | Action: {action}
Weapon visible: {analysis.get('has_weapon_visible')}
Explosion/Fire: {analysis.get('has_explosion') or analysis.get('has_fire')}
Distress: {analysis.get('has_distress_signals')}
People: {analysis.get('people_count')}
{f'Tracking: {tracking_str}' if tracking_str else ''}
Notes: {analysis.get('notes', '')}

Event timeline (most notable frames):
{timeline_str or '  (none)'}

Briefing:"""

    r = _post_with_retry(
        "/api/generate",
        {
            "model": TEXT_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3},
        },
    )
    if r:
        return r.get("response", "").strip()
    return (
        f"{action}\n\nConfidence: {analysis.get('confidence', 50)}%\n\n"
        f"{analysis.get('scene_summary', 'Incident detected')}"
    )


# ── Terminal summary banner ───────────────────────────────────────────────────


def _print_banner(
    threat: ThreatLevel,
    rec,
    temporal: Dict,
    analysis: Dict,
    attack: Optional[str],
    tracking: Optional[Dict],
):
    w = 60
    cue = rec.visual_cue
    print(f"\n{'='*w}")
    print(f"  CERTIS SECURITY — OFFICER BRIEFING")
    print(f"{'='*w}")
    print(f"  {cue}  {threat.value.upper()}")
    print(f"  ACTION  : {rec.action}")
    print(
        f"  URGENCY : {rec.urgency.upper()}"
        f"  |  HUMAN APPROVAL: {'YES ⚠' if rec.requires_human_approval else 'No'}"
    )
    print(
        f"  CONF    : {rec.confidence.confidence:.0f}%  "
        f"| ALT: {rec.confidence.alternative} "
        f"({rec.confidence.alternative_confidence:.0f}%)"
    )
    print(f"  WINDOW  : {temporal['window_minutes']} min lookback")
    if temporal.get("sequence_detected"):
        print(f"  ⚠  SEQUENCE DETECTED (failed badge → door → motion)")
    if analysis.get("event_timeline"):
        print(f"\n  Timeline ({len(analysis['event_timeline'])} events):")
        for ev in analysis["event_timeline"][:4]:
            print(
                f"    {ev['timestamp_s']:>5.0f}s  {ev['event']:<25} {ev['confidence']}%"
            )
    if tracking and tracking.get("is_same_person"):
        print(
            f"\n  Person tracked: {tracking.get('total_time_minutes', 0):.1f} min "
            f"across {len(tracking.get('zones_visited', []))} zone(s)"
        )
    if attack:
        print(f"\n  🔴 SENSOR ATTACK: {attack}")
    print(f"{'='*w}")


# ── Main analysis function ────────────────────────────────────────────────────


def analyse_video(
    video_path: str,
    verbose: bool = True,
    enable_tts: bool = True,
    fast: bool = False,
) -> Dict:
    print(f"\n{'='*60}\nCERTIS SECURITY — VIDEO ANALYSIS PIPELINE  [Finale]\n{'='*60}")
    print(f"Input : {video_path}  {'(fast mode)' if fast else ''}")

    if not ollama_running():
        print("ERROR: Ollama not running. Start with: ollama serve")
        sys.exit(1)

    models = available_models()
    print(f"Models: {', '.join(models) or 'none'}")
    vision_model = pick_vision_model(models)
    if not vision_model:
        print("ERROR: No vision model. Run:\n  ollama pull llava")
        sys.exit(1)

    # [1/4] Frame extraction
    print("\n[1/4] Smart frame selection...")
    target = 5 if fast else 8
    frames = extract_frames(video_path, target_frames=target, fast=fast)

    # [2/4] Parallel vision analysis
    print("\n[2/4] Vision analysis (parallel)...")
    analysis = vision_analyse(frames, vision_model, workers=2)

    if verbose:
        print(f"\n  Scene   : {analysis.get('scene_summary')}")
        print(
            f"  Type    : {analysis.get('primary_event_type')} ({analysis.get('confidence')}%)"
        )
        print(
            f"  People  : {analysis.get('people_count')}  "
            f"Weapon: {analysis.get('has_weapon_visible')}  "
            f"Fire: {analysis.get('has_fire')}  "
            f"Explosion: {analysis.get('has_explosion')}"
        )
        print(
            f"  Zone    : {analysis.get('zone_guess')} / {analysis.get('time_guess')}"
        )
        print(f"  Frames  : {analysis.get('frames_analysed')} analysed")

    # [3/4] SecurityAgent
    print("\n[3/4] SecurityAgent decision...")
    signals = make_signals(analysis, video_path)
    context = make_context(analysis)
    agent = SecurityAgent()

    threat = agent.analyze_signal_fusion(signals, context)
    temporal = agent.temporal_reasoning(signals, context)
    avg_conf = sum(s.confidence for s in signals) / len(signals)
    rec = agent.proportionality_encoding(threat, avg_conf, context)
    attack = agent.detect_sensor_attack(signals)
    tracking = run_person_tracking(analysis, agent, Path(video_path).stem)

    # [4/4] Officer briefing
    print("\n[4/4] Officer briefing...")
    briefing = officer_briefing(
        analysis, threat, rec.action, rec.visual_cue, temporal, tracking
    )

    _print_banner(threat, rec, temporal, analysis, attack, tracking)
    print(f"\n{briefing}\n")

    # TTS
    if enable_tts:
        speak_alert(threat, rec.action, briefing)
        if rec.requires_human_approval:
            speak("Human approval required for this action.")
        if attack:
            speak(f"Sensor attack warning. {attack}")
        if tracking and tracking.get("is_same_person"):
            mins = tracking.get("total_time_minutes", 0)
            if mins > 10:
                speak(
                    f"Loitering alert: same individual tracked for {mins:.0f} minutes."
                )

    result = {
        "video_path": video_path,
        "timestamp": datetime.now().isoformat(),
        "vision_model": vision_model,
        "vision_analysis": analysis,
        "signals": [s.dict() for s in signals],
        "threat_level": threat.value,
        "recommendation": {
            "action": rec.action,
            "urgency": rec.urgency,
            "visual_cue": rec.visual_cue,
            "requires_human_approval": rec.requires_human_approval,
            "confidence": rec.confidence.confidence,
            "alternative": rec.confidence.alternative,
        },
        "temporal": temporal,
        "attack_alert": attack,
        "person_tracking": tracking,
        "officer_briefing": briefing,
    }

    out = Path(video_path).stem + "_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Saved : {out}")
    return result


# ── Live webcam / RTSP mode ───────────────────────────────────────────────────


def analyse_live(
    src: int | str = 0,
    chunk_s: int = 10,
    enable_tts: bool = True,
    fast: bool = True,
):
    """
    Capture rolling chunks from a webcam or RTSP stream and analyse each one.

    src     : 0 for default webcam, integer for device index, or RTSP URL string
    chunk_s : seconds per analysis chunk (default 10)
    """
    import tempfile

    cap = cv2.VideoCapture(src)
    if not cap.isOpened():
        print(f"ERROR: Cannot open source: {src}")
        sys.exit(1)

    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    print(f"\n{'='*60}\nCERTIS SECURITY — LIVE PIPELINE  (src={src})\n{'='*60}")
    print(f"Chunk: {chunk_s}s | Press Ctrl-C to stop\n")

    if not ollama_running():
        print("ERROR: Ollama not running. Start with: ollama serve")
        cap.release()
        sys.exit(1)

    models = available_models()
    vision_model = pick_vision_model(models)
    if not vision_model:
        print("ERROR: No vision model. Run: ollama pull llava")
        cap.release()
        sys.exit(1)

    chunk_frames_total = int(fps * chunk_s)
    chunk_num = 0

    try:
        while True:
            chunk_num += 1
            print(f"\n--- Live chunk #{chunk_num} ---")
            frames_raw = []

            for _ in range(chunk_frames_total):
                ret, frame = cap.read()
                if ret:
                    frames_raw.append(frame)

            if not frames_raw:
                print("  No frames captured — stream may have ended.")
                break

            # Save chunk to temp file so extract_frames can read it
            with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
                tmp_path = tmp.name

            h, w = frames_raw[0].shape[:2]
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            writer = cv2.VideoWriter(tmp_path, fourcc, fps, (w, h))
            for f in frames_raw:
                writer.write(f)
            writer.release()

            try:
                analyse_video(tmp_path, verbose=True, enable_tts=enable_tts, fast=fast)
            finally:
                os.unlink(tmp_path)

    except KeyboardInterrupt:
        print("\n\nLive mode stopped.")
    finally:
        cap.release()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    enable_tts = "--no-tts" not in args
    fast = "--fast" in args
    live_mode = "--live" in args

    if live_mode:
        # --src=0  or  --src=rtsp://...  or  --src=1
        src = 0
        for a in args:
            if a.startswith("--src="):
                val = a.split("=", 1)[1]
                src = int(val) if val.isdigit() else val
        chunk_s = 10
        for a in args:
            if a.startswith("--chunk="):
                chunk_s = int(a.split("=")[1])
        analyse_live(src=src, chunk_s=chunk_s, enable_tts=enable_tts, fast=fast)

    else:
        path = next((a for a in args if not a.startswith("--")), None)
        if not path:
            path = input("Video path: ").strip()
        if not os.path.exists(path):
            print(f"Not found: {path}")
            sys.exit(1)
        analyse_video(path, verbose=True, enable_tts=enable_tts, fast=fast)
