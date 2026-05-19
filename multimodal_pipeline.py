"""
Certis Security — Multimodal Fusion Pipeline
=============================================
Flow:
  Video file  ──┐
                ├──> [Video Analysis]  ──> video_signals
                │                          │
  Audio track ──┤                          ├──> [Signal Fusion Layer]
  (or .wav)   ──┘──> [Audio Analysis] ──> audio_signals
                                           │
                                    [SecurityAgent]
                                           │
                                    [Ollama Briefing]  ←── FULL context from both
                                           │
                                    [TTS output]

Why fusion beats running them separately
-----------------------------------------
  • Video alone: LLaVA misses small weapons, dark knives, partially-hidden objects
  • Audio alone: Acoustic rules miss gunshots when background noise is high
  • Together:  Video "person holding object" + Audio "impulsive transient" = weapon
               Video "smoke/HSV fire hit" + Audio "crackling" = confirmed fire
               Video "calm scene" + Audio "distress keywords" = panic call / lift alarm
               Any single modality with low confidence gets corroborated or overruled

Signal fusion rules applied
----------------------------
  1. CORROBORATION  — same event type in both → confidence boosted (+15%)
  2. ESCALATION     — audio detects gunshot/explosion even if video misses it → CRITICAL
  3. CONTEXT FILL   — video provides zone/time/people; audio provides sounds/transcript
  4. SUPPRESSION    — both say normal_activity → LOW, suppresses individual noise
  5. WEAPON COMBO   — video has suspicious_behaviour OR person + audio has weapon_audio
                      → force HIGH/CRITICAL regardless of individual confidence

Usage
-----
  python multimodal_pipeline.py clip.mp4              # extracts audio from video
  python multimodal_pipeline.py clip.mp4 clip.wav     # separate audio file
  python multimodal_pipeline.py clip.mp4 --no-tts
  python multimodal_pipeline.py clip.mp4 --fast
  python multimodal_pipeline.py clip.mp4 --video-only  # skip audio
  python multimodal_pipeline.py clip.wav --audio-only  # skip video
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from video_analysis_pipeline import (
    ollama_running,
    available_models,
    pick_vision_model,
    extract_frames,
    vision_analyse,
    make_signals as video_make_signals,
    make_context as video_make_context,
    run_person_tracking,  # ← ADD THIS
    _post_with_retry,
    TEXT_MODEL,
    speak,
    speak_alert,
    _print_banner,
)
from models import EventType, Signal, SecurityContext, ThreatLevel
from security_agent import SecurityAgent

# ── Import sub-pipelines (re-use all existing code as-is) ────────────────────

from video_analysis_pipeline import (
    ollama_running,
    available_models,
    pick_vision_model,
    extract_frames,
    vision_analyse,
    make_signals as video_make_signals,
    make_context as video_make_context,
    run_person_tracking,
    _post_with_retry,
    TEXT_MODEL,
    speak,
    speak_alert,
    _print_banner,
)

try:
    from audio_analysis_pipeline import (
        load_audio_file,
        extract_audio_features,
        rule_classify,
        transcribe_audio,
        ollama_audio_reasoning,
        make_signals as audio_make_signals,
    )

    AUDIO_PIPELINE_OK = True
except ImportError as _e:
    AUDIO_PIPELINE_OK = False
    print(f"⚠  Audio pipeline import failed: {_e}")
    print("   Run: pip install librosa openai-whisper soundfile")

# ── Severity table (shared with both pipelines) ─────────────────────────────

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


def _sev(event_type: str) -> int:
    return SEVERITY.index(event_type) if event_type in SEVERITY else 0


# ── Step 1: Extract audio track from video ───────────────────────────────────


def extract_audio_from_video(video_path: str) -> Optional[str]:
    """
    Use ffmpeg to pull the audio track out of the video as a WAV file.
    Returns path to temp WAV, or None if ffmpeg unavailable / no audio track.
    """
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        tmp_path = tmp.name
        tmp.close()

        result = subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-i",
                video_path,
                "-vn",  # no video
                "-acodec",
                "pcm_s16le",  # raw WAV
                "-ar",
                "22050",  # match librosa SR
                "-ac",
                "1",  # mono
                tmp_path,
            ],
            capture_output=True,
            timeout=60,
        )

        if result.returncode != 0 or not os.path.exists(tmp_path):
            os.unlink(tmp_path)
            return None

        # Check file has content
        if os.path.getsize(tmp_path) < 1000:
            os.unlink(tmp_path)
            return None

        print(f"  ✓ Audio extracted to temp WAV ({os.path.getsize(tmp_path)//1024} KB)")
        return tmp_path

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  ⚠  ffmpeg not available or failed: {e}")
        print("     Install ffmpeg: https://ffmpeg.org/download.html")
        return None


# ── Step 2: Run both analyses in sequence ────────────────────────────────────


def run_video_analysis(video_path: str, vision_model: str, fast: bool) -> Dict:
    target = 5 if fast else 8
    print("\n  [Video] Smart frame selection...")
    frames = extract_frames(video_path, target_frames=target, fast=fast)
    print("\n  [Video] Parallel vision analysis...")
    analysis = vision_analyse(frames, vision_model, workers=2)
    return analysis


def run_audio_analysis(audio_path: str) -> Optional[Dict]:
    if not AUDIO_PIPELINE_OK:
        print("  ⚠  Audio pipeline unavailable — skipping audio analysis")
        return None

    try:
        print("\n  [Audio] Loading audio...")
        y, sr = load_audio_file(audio_path)

        print("\n  [Audio] Extracting acoustic features...")
        feat = extract_audio_features(y, sr)
        rule_label, rule_conf = rule_classify(feat)
        print(f"         Rule pre-class: {rule_label} ({rule_conf}%)")

        print("\n  [Audio] Whisper transcription...")
        transcript = transcribe_audio(audio_path)
        text_preview = transcript.get("text", "")[:80]
        if text_preview:
            print(f'         "{text_preview}"')
        kws = transcript.get("distress_keywords", [])
        if kws:
            print(f"         Distress keywords: {kws}")

        print("\n  [Audio] Ollama reasoning...")
        analysis = ollama_audio_reasoning(feat, transcript, rule_label, rule_conf)
        analysis["transcript_text"] = transcript.get("text", "")
        analysis["distress_keywords"] = transcript.get("distress_keywords", [])
        analysis["_rule_label"] = rule_label
        analysis["_rule_conf"] = rule_conf
        return analysis

    except Exception as e:
        print(f"  ⚠  Audio analysis failed: {e}")
        return None


# ── Step 3: Multimodal signal fusion ─────────────────────────────────────────


def fuse_signals(
    video_analysis: Optional[Dict],
    audio_analysis: Optional[Dict],
    source_label: str,
) -> Tuple[List[Signal], SecurityContext, Dict]:
    """
    Core fusion logic.  Takes both analyses and produces a unified signal list
    that the SecurityAgent can work with.

    Returns (signals, context, fusion_summary)
    """
    signals: List[Signal] = []
    fusion_notes: List[str] = []

    v = video_analysis or {}
    a = audio_analysis or {}

    # Normalize audio analysis fields to avoid KeyError and allow robust fusion
    if audio_analysis:
        for key, default in {
            "primary_event_type": "normal_activity",
            "confidence": 0,
            "has_distress_signals": False,
            "is_panic_call": False,
            "has_weapon_audio": False,
            "has_explosion": False,
            "has_fire_audio": False,
            "transcript_text": "",
            "distress_keywords": [],
        }.items():
            audio_analysis.setdefault(key, default)
        a = audio_analysis

    # ── Produce individual signals from each modality ─────────────────────────
    if video_analysis:
        v_sigs = video_make_signals(video_analysis, source_label + "_video")
        signals.extend(v_sigs)

    if audio_analysis:
        a_sigs = audio_make_signals(audio_analysis, source_label + "_audio")
        signals.extend(a_sigs)

    if not signals:
        # Complete fallback — should never happen in practice
        signals = [
            Signal(
                type=EventType.MOTION_DETECTION,
                confidence=20,
                timestamp=datetime.now(),
                location=source_label,
                metadata={"source": "fallback"},
            )
        ]

    # ── Cross-modal fusion rules ──────────────────────────────────────────────

    v_event = v.get("primary_event_type") or "normal_activity"
    a_event = a.get("primary_event_type") or "normal_activity"
    v_conf = float(v.get("confidence", 0))
    a_conf = float(a.get("confidence", 0))

    v_sev = _sev(v_event)
    a_sev = _sev(a_event)

    # THE FIX: Grab all the raw text the AI generated just in case it forgot the proper tags
    # THE FIX: Only check the actual text sentences the AI wrote, NOT the dictionary keys
    text_to_check = (
        str(a.get("transcript_text", ""))
        + " "
        + str(a.get("scene_summary", ""))
        + " "
        + str(a.get("threat_rationale", ""))
    ).lower()

    # Hunt for distress words ONLY in the text values
    audio_distress = (
        a.get("has_distress_signals") == True
        or a.get("is_panic_call") == True
        or a_sev == _sev("panic_call")
        or any(
            w in text_to_check
            for w in ["stuck", "help", "distress", "scream", "emergency", "panic"]
        )
    )

    # MAKE SURE THIS IS HERE: Hunt for weapon words (Without the bad text search)
    audio_weapon = (
        a.get("has_weapon_audio") == True
        or a.get("has_explosion") == True
        or a_sev >= _sev("gunshot_audio")
    )

    # Rule 1 — CORROBORATION: same event in both modalities
    if v_event == a_event and v_event not in (
        "normal_activity",
        "motion_detection",
        "?",
    ):
        for s in signals:
            s.confidence = min(100, s.confidence + 15)
        fusion_notes.append(
            f"CORROBORATION: both modalities agree on '{v_event}' (+15% confidence)"
        )

    # Rule 2 — AUDIO ESCALATION (Forcing the override)
    if audio_weapon and v_sev < _sev("gunshot_audio"):
        weapon_type = (
            EventType.EXPLOSION
            if a.get("has_explosion") == True
            else EventType.GUNSHOT_AUDIO
        )
        signals.append(
            Signal(
                type=weapon_type,
                confidence=min(100, a_conf + 20),
                timestamp=datetime.now(),
                location=source_label + "_audio_override",
                metadata={
                    "source": "audio_escalation",
                    "reason": "Audio text detected weapon",
                },
            )
        )
        fusion_notes.append("AUDIO ESCALATION: Weapon detected -> injected signal")

    elif audio_distress and v_sev < _sev("panic_call"):
        # FORCE A PANIC CALL SIGNAL SO IT CANNOT BE SUPPRESSED
        signals.append(
            Signal(
                type=EventType.PANIC_CALL,
                confidence=min(100, max(a_conf + 20, 85)),
                timestamp=datetime.now(),
                location=source_label + "_audio_override",
                metadata={
                    "source": "audio_escalation",
                    "reason": "Audio text detected distress/panic",
                },
            )
        )
        fusion_notes.append(
            "AUDIO ESCALATION: Distress detected -> injected PANIC_CALL signal"
        )
        a_sev = _sev("panic_call")  # Force severity high so suppression rule ignores it

    # Rule 3 — WEAPON COMBO: visual suspicious + audio weapon
    visual_suspicious = (
        v.get("has_weapon_visible")
        or v.get("suspicious_behaviour")
        or v_event in ("unauthorized_access", "forced_entry")
    )
    if visual_suspicious and audio_weapon:
        for s in signals:
            s.confidence = min(100, s.confidence + 20)
        signals.append(
            Signal(
                type=EventType.GUNSHOT_AUDIO,
                confidence=min(100, max(v_conf, a_conf) + 15),
                timestamp=datetime.now(),
                location=source_label + "_weapon_combo",
                metadata={
                    "source": "weapon_combination",
                    "reason": "Visual suspicious + audio weapon",
                },
            )
        )
        fusion_notes.append(
            "WEAPON COMBO: visual suspicious behaviour + audio weapon -> CRITICAL escalation"
        )

    # Rule 4 — SUPPRESSION (Only trigger if totally normal)
    both_normal = (v_sev <= _sev("motion_detection")) and (
        a_sev <= _sev("motion_detection")
    )

    if both_normal and not audio_distress and not audio_weapon and len(signals) > 0:
        for s in signals:
            s.confidence = max(10, s.confidence - 20)
        fusion_notes.append(
            "SUPPRESSION: both modalities report normal/low activity — confidence reduced"
        )

    # Rule 5 — PANIC CORROBORATION
    if audio_distress and v.get("has_distress_signals"):
        for s in signals:
            if s.type == EventType.PANIC_CALL:
                s.confidence = min(100, s.confidence + 15)
        fusion_notes.append(
            "PANIC CORROBORATION: distress signals confirmed in both modalities"
        )

    # ── Build unified context (video provides better zone/time context) ───────
    context = SecurityContext(
        zone_type=v.get("zone_guess") or a.get("zone_guess") or "high_security",
        time_of_day=v.get("time_guess") or a.get("time_guess") or "unknown",
        authorized_personnel=[],
        metadata={"source": "multimodal_fusion"},
    )

    fusion_summary = {
        "video_event": v_event,
        "audio_event": a_event,
        "fusion_rules_applied": fusion_notes,
        "total_signals": len(signals),
        "video_confidence": v_conf,
        "audio_confidence": a_conf,
    }

    return signals, context, fusion_summary


# ── Step 4: Officer briefing with full multimodal context ────────────────────


def officer_briefing(
    video_analysis: Optional[Dict],
    audio_analysis: Optional[Dict],
    fusion_summary: Dict,
    threat: ThreatLevel,
    action: str,
    visual_cue: str,
    temporal: Dict,
    tracking: Optional[Dict],
) -> str:
    v = video_analysis or {}
    a = audio_analysis or {}

    # Build timeline string from video
    timeline_str = ""
    for ev in v.get("event_timeline", [])[:4]:
        timeline_str += f"  {ev['timestamp_s']:.0f}s: {ev['event']} ({ev['confidence']}%) — {ev['summary']}\n"

    tracking_str = ""
    if tracking and tracking.get("is_same_person"):
        tracking_str = (
            f"Person tracked for {tracking.get('total_time_minutes', 0):.1f} min "
            f"across {len(tracking.get('zones_visited', []))} zones."
        )

    fusion_rules = "; ".join(fusion_summary.get("fusion_rules_applied", [])) or "none"

    prompt = f"""You are a Certis Security command centre advisor writing a radio briefing for an officer.

IMPORTANT: The threat level and action have already been decided by the security system. You must NOT contradict them. Your job is only to explain WHY in plain language using the evidence below.

=== DECIDED OUTCOME (DO NOT CHANGE) ===
Threat Level: {threat.value.upper()}
Required Action: {action}
Visual Cue: {visual_cue}

=== EVIDENCE ===
VISUAL (CCTV): {v.get('scene_summary', 'No video feed available')}
Events seen: {', '.join(v.get('detected_events', [])) or 'none'}

AUDIO: {a.get('scene_summary', 'No audio available')}
Transcript: "{a.get('transcript_text', '')[:200]}"
Distress keywords: {a.get('distress_keywords', [])}

FUSION RULES APPLIED: {fusion_rules}
{f'Person tracking: {tracking_str}' if tracking_str else ''}

=== INSTRUCTIONS ===
Write exactly 3-4 sentences. No bullet points. No hedging.
Start with: "Officer, ..."
Sentence 1: State what was detected and where.
Sentence 2: State why the threat is {threat.value.upper()}. If distress keywords or transcripts exist, you MUST quote the transcript (e.g., 'The transcript includes "[quote]"').
Sentence 3: State exactly what the officer must do: {action}.
Sentence 4: Proceed with caution or relevant advice.

CRITICAL: Do NOT invent weapons, fires, or explosions unless they are explicitly confirmed in the FUSION RULES or EVIDENCE. Base everything on the transcript and facts provided.
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

    # Validate Ollama's response — reject it if it contradicts the decided threat/action
    if r:
        briefing_text = r.get("response", "").strip()
        # Check that the briefing doesn't contradict the decided action
        action_lower = action.lower()
        briefing_lower = briefing_text.lower()
        # If the briefing mentions a lower-severity action when we decided HIGH+, discard it
        contradicts = False
        if threat.value in ("high", "critical") and any(
            phrase in briefing_lower
            for phrase in [
                "continue passive monitoring",
                "no immediate action",
                "no action required",
                "low risk",
                "medium-level threat",
                "medium level threat",
            ]
        ):
            contradicts = True

        if briefing_text and not contradicts:
            return briefing_text

    # Fallback — always consistent with decided threat/action
    audio_summary = a.get("scene_summary") or a.get("transcript_text", "")[:120]
    video_summary = v.get("scene_summary", "")
    evidence = audio_summary or video_summary or "sensor data"
    fusion_note = fusion_summary.get("fusion_rules_applied", [""])[0]

    fallback_parts = [
        f"Officer, a {threat.value.upper()} threat has been detected.",
        f"Evidence: {evidence}." if evidence else "",
        f"Fusion analysis: {fusion_note}." if fusion_note else "",
        f"Immediate action required: {action}.",
    ]
    return " ".join(p for p in fallback_parts if p)


# ── Terminal banner ───────────────────────────────────────────────────────────


def _print_fusion_banner(
    threat,
    rec,
    temporal,
    fusion_summary,
    video_analysis,
    audio_analysis,
    attack,
    tracking,
):
    w = 64
    print(f"\n{'='*w}")
    print(f"  CERTIS SECURITY — MULTIMODAL OFFICER BRIEFING")
    print(f"{'='*w}")
    print(f"  {rec.visual_cue}  {threat.value.upper()}")
    print(f"  ACTION   : {rec.action}")
    print(
        f"  URGENCY  : {rec.urgency.upper()}  |  HUMAN: {'YES ⚠' if rec.requires_human_approval else 'No'}"
    )
    print(
        f"  CONF     : {rec.confidence.confidence:.0f}%  |  Alt: {rec.confidence.alternative} ({rec.confidence.alternative_confidence:.0f}%)"
    )
    print(f"  WINDOW   : {temporal['window_minutes']} min")

    if video_analysis:
        v_ev = video_analysis.get("primary_event_type", "?")
        v_cf = video_analysis.get("confidence", 0)
        print(f"\n  VIDEO    : {v_ev} ({v_cf}%)")
        print(
            f"             Weapon seen: {video_analysis.get('has_weapon_visible')} | "
            f"Fire: {video_analysis.get('has_fire')} | "
            f"People: {video_analysis.get('people_count')}"
        )

    if audio_analysis:
        a_ev = audio_analysis.get("primary_event_type", "?")
        a_cf = audio_analysis.get("confidence", 0)
        print(f"\n  AUDIO    : {a_ev} ({a_cf}%)")
        print(
            f"             Weapon heard: {audio_analysis.get('has_weapon_audio')} | "
            f"Explosion: {audio_analysis.get('has_explosion')}"
        )
        kws = audio_analysis.get("distress_keywords", [])
        if kws:
            print(f"             Distress kws: {kws}")

    rules = fusion_summary.get("fusion_rules_applied", [])
    if rules:
        print(f"\n  FUSION   :")
        for r in rules:
            print(f"    → {r}")

    if temporal.get("sequence_detected"):
        print(f"\n  ⚠  SEQUENCE DETECTED (failed badge → door → motion)")
    if attack:
        print(f"\n  🔴 SENSOR ATTACK: {attack}")
    if tracking and tracking.get("is_same_person"):
        print(
            f"\n  👤 TRACKING: {tracking.get('total_time_minutes', 0):.1f} min / "
            f"{len(tracking.get('zones_visited', []))} zones"
        )
    print(f"{'='*w}")


# ── Main pipeline ─────────────────────────────────────────────────────────────


def analyse_multimodal(
    video_path: Optional[str] = None,
    audio_path: Optional[str] = None,
    verbose: bool = True,
    enable_tts: bool = True,
    fast: bool = False,
    video_only: bool = False,
    audio_only: bool = False,
) -> Dict:

    print(f"\n{'='*64}")
    print(f"CERTIS SECURITY — MULTIMODAL FUSION PIPELINE")
    print(f"{'='*64}")
    if video_path:
        print(f"Video : {video_path}")
    if audio_path:
        print(f"Audio : {audio_path}")

    if not ollama_running():
        print("ERROR: Ollama not running. Start with: ollama serve")
        sys.exit(1)

    models = available_models()
    print(f"Models: {', '.join(models) or 'none'}")

    # ── Figure out what we're working with ────────────────────────────────────
    run_video = bool(video_path) and not audio_only
    run_audio = not video_only

    # If only a video was given and audio is wanted, extract the audio track
    extracted_audio_path = None
    if run_video and run_audio and video_path and not audio_path:
        print("\n[0/4] Extracting audio track from video...")
        extracted_audio_path = extract_audio_from_video(video_path)
        if extracted_audio_path:
            audio_path = extracted_audio_path
        else:
            print("  No audio track found (or ffmpeg missing) — proceeding video-only")
            run_audio = False

    # ── [1/4] Video analysis ──────────────────────────────────────────────────
    video_analysis = None
    if run_video and video_path:
        vision_model = pick_vision_model(models)
        if not vision_model:
            print("ERROR: No vision model. Run: ollama pull llava")
            sys.exit(1)
        print(f"\n[1/4] Video analysis  (model={vision_model}) ...")
        video_analysis = run_video_analysis(video_path, vision_model, fast)

        if verbose and video_analysis:
            print(f"\n       Scene   : {video_analysis.get('scene_summary')}")
            print(
                f"       Type    : {video_analysis.get('primary_event_type')} ({video_analysis.get('confidence')}%)"
            )
            print(
                f"       Weapon  : {video_analysis.get('has_weapon_visible')}  "
                f"Fire: {video_analysis.get('has_fire')}  "
                f"People: {video_analysis.get('people_count')}"
            )
    else:
        print("\n[1/4] Video analysis — SKIPPED")

    # ── [2/4] Audio analysis ──────────────────────────────────────────────────
    audio_analysis = None
    if run_audio and audio_path:
        print(f"\n[2/4] Audio analysis  (file={Path(audio_path).name}) ...")
        audio_analysis = run_audio_analysis(audio_path)

        if verbose and audio_analysis:
            print(
                f"\n       Type    : {audio_analysis.get('primary_event_type')} ({audio_analysis.get('confidence')}%)"
            )
            print(f"       Summary : {audio_analysis.get('scene_summary')}")
            print(
                f"       Weapon  : {audio_analysis.get('has_weapon_audio')}  "
                f"Explosion: {audio_analysis.get('has_explosion')}"
            )
    else:
        print("\n[2/4] Audio analysis — SKIPPED")

    # ── [3/4] Signal fusion + SecurityAgent ───────────────────────────────────
    print("\n[3/4] Multimodal signal fusion + SecurityAgent...")
    source_label = Path(video_path or audio_path or "incident").stem
    signals, context, fusion_summary = fuse_signals(
        video_analysis, audio_analysis, source_label
    )

    agent = SecurityAgent()
    threat = agent.analyze_signal_fusion(signals, context)
    temporal = agent.temporal_reasoning(signals, context)
    avg_conf = sum(s.confidence for s in signals) / len(signals)
    rec = agent.proportionality_encoding(threat, avg_conf, context)
    attack = agent.detect_sensor_attack(signals)
    tracking = (
        run_person_tracking(video_analysis or {}, agent, source_label)
        if video_analysis
        else None
    )

    if verbose:
        print(f"\n  Threat   : {threat.value.upper()}  |  {rec.visual_cue}")
        print(f"  Action   : {rec.action}")
        print(f"  Signals  : {len(signals)} total after fusion")
        print(f"  Fusion   :")
        for note in fusion_summary.get("fusion_rules_applied", []):
            print(f"    → {note}")

    # ── [4/4] Officer briefing ────────────────────────────────────────────────
    print("\n[4/4] Generating officer briefing...")
    briefing = officer_briefing(
        video_analysis,
        audio_analysis,
        fusion_summary,
        threat,
        rec.action,
        rec.visual_cue,
        temporal,
        tracking,
    )

    _print_fusion_banner(
        threat,
        rec,
        temporal,
        fusion_summary,
        video_analysis,
        audio_analysis,
        attack,
        tracking,
    )
    print(f"\n{briefing}\n")

    # ── TTS ───────────────────────────────────────────────────────────────────
    if enable_tts:
        speak_alert(threat, rec.action, briefing)
        if rec.requires_human_approval:
            speak("Human approval required for this action.")
        if attack:
            speak(f"Sensor attack warning. {attack}")

    # ── Cleanup temp file ─────────────────────────────────────────────────────
    if extracted_audio_path and os.path.exists(extracted_audio_path):
        os.unlink(extracted_audio_path)

    # ── Save result ───────────────────────────────────────────────────────────
    result = {
        "timestamp": datetime.now().isoformat(),
        "video_path": video_path,
        "audio_path": audio_path,
        "video_analysis": video_analysis,
        "audio_analysis": audio_analysis,
        "fusion_summary": fusion_summary,
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

    out_stem = Path(video_path or audio_path or "incident").stem
    out_path = out_stem + "_multimodal_analysis.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Saved : {out_path}")
    return result


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    enable_tts = "--no-tts" not in args
    fast = "--fast" in args
    video_only = "--video-only" in args
    audio_only = "--audio-only" in args

    # Collect positional (non-flag) arguments
    positional = [a for a in args if not a.startswith("--")]

    video_path = None
    audio_path = None

    for p in positional:
        ext = Path(p).suffix.lower()
        if ext in (".mp4", ".avi", ".mov", ".mkv", ".webm"):
            video_path = p
        elif ext in (".wav", ".mp3", ".flac", ".ogg", ".m4a"):
            audio_path = p

    if not video_path and not audio_path:
        inp = input("Path to video (or audio) file: ").strip()
        ext = Path(inp).suffix.lower()
        if ext in (".wav", ".mp3", ".flac", ".ogg", ".m4a"):
            audio_path = inp
        else:
            video_path = inp

    for p in filter(None, [video_path, audio_path]):
        if not os.path.exists(p):
            print(f"File not found: {p}")
            sys.exit(1)

    analyse_multimodal(
        video_path=video_path,
        audio_path=audio_path,
        enable_tts=enable_tts,
        fast=fast,
        video_only=video_only,
        audio_only=audio_only,
    )
