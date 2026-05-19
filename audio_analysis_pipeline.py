"""
Certis Security — Audio Analysis Pipeline
==========================================
Flow (file mode) : Audio file  -> Feature extraction (librosa)
                               -> Speech transcription (Whisper)
                               -> Ollama text reasoning
                               -> Signal objects -> SecurityAgent logic
                               -> Ollama officer briefing -> TTS output

Flow (mic mode)  : Live mic    -> Chunk capture (pyaudio/sounddevice)
                               -> same pipeline per chunk

Acoustic events detected
------------------------
  GUNSHOT / EXPLOSION  — short, high-energy transient, broad frequency spike
  FIRE / SMOKE         — crackling texture (high ZCR, moderate energy)
  GLASS_BREAK          — sharp high-frequency burst
  SCREAMING / PANIC    — sustained high-pitch, high energy; confirmed by Whisper transcript
  PANIC_CALL           — Whisper detects distress keywords
  FORCED_ENTRY         — repeated loud impact pattern
  NORMAL               — ambient / speech

Dependencies (install once)
----------------------------
  pip install openai-whisper librosa soundfile numpy scipy pyttsx3
  pip install sounddevice   # for live mic
  pip install pyaudio       # alternative mic backend

Usage
-----
  # Test on a file:
  python audio_analysis_pipeline.py path/to/clip.wav

  # Live mic (press Ctrl-C to stop after each chunk):
  python audio_analysis_pipeline.py --mic

  # Disable TTS:
  python audio_analysis_pipeline.py path/to/clip.wav --no-tts
"""

import json
import os
import re
import sys
import time
import urllib.request
import warnings
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import numpy as np

warnings.filterwarnings("ignore")  # suppress librosa/numba noise

# ── Optional heavy imports (fail gracefully) ────────────────────────────────

try:
    import librosa

    LIBROSA_OK = True
except ImportError:
    LIBROSA_OK = False
    print("⚠  librosa not found. Run: pip install librosa soundfile")

try:
    import whisper as _whisper_mod

    WHISPER_OK = True
except ImportError:
    WHISPER_OK = False
    print("⚠  openai-whisper not found. Run: pip install openai-whisper")

try:
    import sounddevice as sd

    SD_OK = True
except (ImportError, OSError):
    SD_OK = False

from models import Signal, SecurityContext, EventType, ThreatLevel
from security_agent import SecurityAgent

# ── Re-use TTS helpers from video pipeline ───────────────────────────────────

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
        print("⚠  pyttsx3 not found. Run: pip install pyttsx3")
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
    for pat, rep in {r"\bID\b": "identification", r"\bCCTV\b": "C C T V"}.items():
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
        print(f"TTS error: {e}")


def speak_alert(threat: ThreatLevel, action: str, briefing: str):
    if threat == ThreatLevel.CRITICAL:
        speak(f"Critical audio threat detected. {action}. Immediate response required.")
        speak(_truncate_to_sentences(briefing, 250))
    elif threat == ThreatLevel.HIGH:
        speak(f"High audio threat. {action}.")
        speak(_truncate_to_sentences(briefing, 250))
    else:
        speak(f"{action}. {_truncate_to_sentences(briefing, 220)}")


# ── Ollama helpers ───────────────────────────────────────────────────────────

OLLAMA_BASE = "http://localhost:11434"
TEXT_MODEL = "llama3.2"


def _post(endpoint, payload):
    url = f"{OLLAMA_BASE}{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def ollama_running() -> bool:
    try:
        urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return True
    except Exception:
        return False


# ── Step 1: Load audio ───────────────────────────────────────────────────────

SR = 22050  # target sample rate
MIC_DURATION = 10  # seconds per live chunk


def load_audio_file(path: str) -> Tuple[np.ndarray, int]:
    """Load any audio file to mono float32 numpy array."""
    if not LIBROSA_OK:
        raise RuntimeError("librosa required: pip install librosa soundfile")
    y, sr = librosa.load(path, sr=SR, mono=True)
    duration = len(y) / sr
    print(f"  Loaded: {duration:.1f}s @ {sr}Hz  ({len(y)} samples)")
    return y, sr


def capture_mic_chunk(duration: int = MIC_DURATION) -> Tuple[np.ndarray, int]:
    """Record a single chunk from the default microphone."""
    if not SD_OK:
        raise RuntimeError("sounddevice required: pip install sounddevice")
    print(f"  🎙  Recording {duration}s from microphone...")
    audio = sd.rec(int(duration * SR), samplerate=SR, channels=1, dtype="float32")
    sd.wait()
    y = audio.flatten()
    print(f"  Captured {len(y)} samples")
    return y, SR


# ── Step 2: Acoustic feature extraction ─────────────────────────────────────


def extract_audio_features(y: np.ndarray, sr: int) -> Dict:
    """
    Extract acoustic features used for event classification.

    Returns a dict of scalar/list features that the Ollama reasoning step
    and the rule-based classifier both consume.
    """
    if not LIBROSA_OK:
        return {"error": "librosa not available"}

    duration = len(y) / sr

    # — Energy / loudness —
    rms = librosa.feature.rms(y=y)[0]
    rms_mean = float(np.mean(rms))
    rms_max = float(np.max(rms))
    rms_std = float(np.std(rms))

    # — Zero Crossing Rate (high = crackling/fire, noise) —
    zcr = librosa.feature.zero_crossing_rate(y)[0]
    zcr_mean = float(np.mean(zcr))

    # — Spectral centroid (brightness) —
    centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
    centroid_mean = float(np.mean(centroid))

    # — Spectral rolloff (how much energy in upper freqs) —
    rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr, roll_percent=0.85)[0]
    rolloff_mean = float(np.mean(rolloff))

    # — MFCCs (timbral texture, 13 coefficients) —
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    mfcc_means = [float(np.mean(c)) for c in mfccs]

    # — Onset detection (transient density — gunshots = single sharp onset) —
    onset_frames = librosa.onset.onset_detect(y=y, sr=sr, units="time")
    onset_count = len(onset_frames)
    onset_density = onset_count / max(duration, 0.1)  # onsets per second

    # — Peak transient detection —
    # A gunshot/explosion = single very loud brief spike
    peak_rms = float(np.max(rms))
    peak_ratio = float(peak_rms / (rms_mean + 1e-9))  # how spiky vs average

    # — High-frequency energy ratio —
    # Gunshots, glass break = lots of energy above 4 kHz
    S = np.abs(librosa.stft(y))
    freqs = librosa.fft_frequencies(sr=sr)
    hi_mask = freqs > 4000
    lo_mask = freqs <= 4000
    hi_energy = float(np.mean(S[hi_mask, :]))
    lo_energy = float(np.mean(S[lo_mask, :]) + 1e-9)
    hf_ratio = hi_energy / lo_energy

    # — Sustained vs impulsive — (std of RMS over time)
    is_impulsive = bool(peak_ratio > 6.0)
    is_sustained = bool(rms_std < 0.02 and rms_mean > 0.01)
    is_crackling = bool(zcr_mean > 0.15 and rms_mean > 0.005)

    return {
        "duration_s": round(duration, 2),
        "rms_mean": round(rms_mean, 5),
        "rms_max": round(rms_max, 4),
        "rms_std": round(rms_std, 5),
        "peak_ratio": round(peak_ratio, 2),
        "zcr_mean": round(zcr_mean, 4),
        "centroid_hz": round(centroid_mean, 1),
        "rolloff_hz": round(rolloff_mean, 1),
        "hf_ratio": round(hf_ratio, 4),
        "onset_count": onset_count,
        "onset_density": round(onset_density, 3),
        "mfcc_means": [round(v, 2) for v in mfcc_means],
        "is_impulsive": is_impulsive,
        "is_sustained": is_sustained,
        "is_crackling": is_crackling,
    }


# ── Step 3: Rule-based acoustic classifier ──────────────────────────────────

ACOUSTIC_EVENT_LABELS = {
    "gunshot": "POSSIBLE GUNSHOT — sharp transient, broadband spike",
    "explosion": "POSSIBLE EXPLOSION — high energy, very broad transient",
    "glass_break": "POSSIBLE GLASS BREAK — high-freq burst, brief",
    "fire_crackling": "POSSIBLE FIRE — sustained crackling texture",
    "screaming": "POSSIBLE SCREAMING / DISTRESS — sustained high-energy voice",
    "forced_entry": "POSSIBLE FORCED ENTRY — repeated impact pattern",
    "normal_speech": "NORMAL SPEECH / AMBIENT",
    "silence": "SILENCE / VERY LOW ACTIVITY",
}


def rule_classify(feat: Dict) -> Tuple[str, float]:
    """
    Fast heuristic pre-classifier.
    Returns (event_label, confidence_0_to_100).

    These thresholds are intentionally conservative — the Ollama reasoning
    step is the final arbiter.
    """
    if feat.get("error"):
        return "normal_speech", 30.0

    rms_mean = feat["rms_mean"]
    peak_ratio = feat["peak_ratio"]
    hf_ratio = feat["hf_ratio"]
    zcr_mean = feat["zcr_mean"]
    onset_cnt = feat["onset_count"]
    is_imp = feat["is_impulsive"]
    is_crack = feat["is_crackling"]
    duration = feat["duration_s"]

    # Silence
    if rms_mean < 0.002:
        return "silence", 90.0

    # Gunshot: single sharp transient, very high peak ratio, short event
    if is_imp and peak_ratio > 8 and hf_ratio > 0.3 and onset_cnt <= 3:
        conf = min(95, 60 + (peak_ratio - 8) * 3 + hf_ratio * 20)
        return "gunshot", round(conf, 1)

    # Explosion: similar to gunshot but higher overall energy, possibly longer
    if is_imp and peak_ratio > 5 and rms_mean > 0.05 and duration > 0.5:
        return "explosion", 75.0

    # Glass break: very brief, very high frequency content
    if hf_ratio > 0.6 and duration < 2.0 and peak_ratio > 4:
        return "glass_break", 70.0

    # Fire crackling: high ZCR, sustained, moderate energy
    if is_crack and feat["is_sustained"] and duration > 3:
        return "fire_crackling", 65.0

    # Screaming / Distress: high energy sustained, high centroid (female scream ~1-3kHz)
    if (
        rms_mean > 0.03
        and feat["is_sustained"]
        and feat["centroid_hz"] > 1500
        and not is_imp
    ):
        return "screaming", 60.0

    # Forced entry: multiple loud impacts (high onset density + high energy)
    if onset_cnt > 5 and feat["onset_density"] > 1.5 and rms_mean > 0.02:
        return "forced_entry", 65.0

    return "normal_speech", 40.0


# ── Step 4: Whisper speech transcription ─────────────────────────────────────

_whisper_model = None


def _get_whisper():
    global _whisper_model
    if _whisper_model is None and WHISPER_OK:
        print("  Loading Whisper (base)...")
        _whisper_model = _whisper_mod.load_model("base")
    return _whisper_model


DISTRESS_KEYWORDS = [
    "help",
    "fire",
    "gun",
    "shot",
    "bomb",
    "attack",
    "emergency",
    "intruder",
    "danger",
    "please",
    "stop",
    "police",
    "hurt",
    "bleeding",
    "trapped",
    "locked",
    "break",
    "scream",
]


def transcribe_audio(audio_path: str) -> Dict:
    """
    Run Whisper on the audio file and check for distress keywords.
    Returns transcript text + detected distress flags.
    """
    model = _get_whisper()
    if model is None:
        return {"text": "", "distress_keywords": [], "is_distress": False}

    try:
        result = model.transcribe(audio_path, language="en", fp16=False)
        text = result.get("text", "").strip().lower()
    except Exception as e:
        print(f"  Whisper error: {e}")
        return {"text": "", "distress_keywords": [], "is_distress": False}

    found = [kw for kw in DISTRESS_KEYWORDS if kw in text]
    return {
        "text": text,
        "distress_keywords": found,
        "is_distress": len(found) >= 1,
        "distress_count": len(found),
    }


# ── Step 5: Ollama audio reasoning ───────────────────────────────────────────

AUDIO_REASONING_PROMPT = """\
You are an expert acoustic security analyst at Certis Security.
Analyse the audio features and transcript below.
Reply ONLY with valid JSON, no markdown, no extra text.

CRITICAL INSTRUCTION: If the RULE-BASED PRE-CLASSIFICATION is "silence" or the volume (rms_mean) is very low, you MUST classify it as "normal_activity". Do not invent sounds that are not there. Set all threat flags to false.

{{
  "primary_event_type": "<one of: gunshot_audio | explosion | fire | panic_call | forced_entry | glass_break | screaming | loitering | motion_detection | normal_activity>",
  "confidence": <0-100>,
  "scene_summary": "<one sentence describing the sound, or 'Silence detected' if quiet>",
  "detected_sounds": ["<list of sounds, or empty list if quiet>"],
  "has_distress_signals": <true|false>,
  "has_weapon_audio": <true|false>,
  "has_explosion": <true|false>,
  "has_fire_audio": <true|false>,
  "is_panic_call": <true|false>,
  "threat_rationale": "<one sentence explaining the threat level, or 'No threat detected'>",
  "zone_guess": "<high_security|low_security|public_space|critical_infrastructure>",
  "notes": "<anything else relevant>"
}}

ACOUSTIC FEATURES:
{features}

WHISPER TRANSCRIPT: "{transcript}"
DISTRESS KEYWORDS DETECTED: {distress_kws}
RULE-BASED PRE-CLASSIFICATION: {rule_label} (confidence {rule_conf}%)

Use all the above together to make your classification. Stick strictly to the data.
"""


def ollama_audio_reasoning(
    feat: Dict, transcript: Dict, rule_label: str, rule_conf: float
) -> Dict:
    prompt = AUDIO_REASONING_PROMPT.format(
        features=json.dumps(feat, indent=2),
        transcript=transcript.get("text", ""),
        distress_kws=transcript.get("distress_keywords", []),
        rule_label=rule_label,
        rule_conf=rule_conf,
    )
    try:
        r = _post(
            "/api/generate",
            {
                "model": TEXT_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            },
        )
        raw = r.get("response", "").strip()
        # strip markdown fences if model adds them
        raw = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
        return json.loads(raw)
    except Exception as e:
        print(f"  Ollama audio reasoning error: {e}")
        # Fallback: use rule-based result
        return {
            "primary_event_type": _rule_to_event_type(rule_label),
            "confidence": rule_conf,
            "scene_summary": f"Audio event: {rule_label}",
            "detected_sounds": [rule_label],
            "has_distress_signals": transcript.get("is_distress", False),
            "has_weapon_audio": rule_label == "gunshot",
            "has_explosion": rule_label == "explosion",
            "has_fire_audio": rule_label == "fire_crackling",
            "is_panic_call": transcript.get("is_distress", False),
            "threat_rationale": f"Rule-based classification: {rule_label}",
            "zone_guess": "high_security",
            "notes": f"Whisper: {transcript.get('text', '')[:100]}",
        }


def _rule_to_event_type(label: str) -> str:
    mapping = {
        "gunshot": "gunshot_audio",
        "explosion": "explosion",
        "glass_break": "forced_entry",
        "fire_crackling": "fire",
        "screaming": "panic_call",
        "forced_entry": "forced_entry",
        "silence": "normal_activity",
        "normal_speech": "normal_activity",
    }
    return mapping.get(label, "motion_detection")


# ── Step 6: Build Signal + Context ───────────────────────────────────────────

EMAP = {
    "gunshot_audio": EventType.GUNSHOT_AUDIO,
    "explosion": EventType.EXPLOSION,
    "fire": EventType.FIRE,
    "arson": EventType.ARSON,
    "panic_call": EventType.PANIC_CALL,
    "forced_entry": EventType.FORCED_ENTRY,
    "glass_break": EventType.FORCED_ENTRY,
    "screaming": EventType.PANIC_CALL,
    "unauthorized_access": EventType.UNAUTHORIZED_ACCESS,
    "loitering": EventType.LOITERING,
    "motion_detection": EventType.MOTION_DETECTION,
    "normal_activity": EventType.MOTION_DETECTION,
}


def make_signals(analysis: Dict, source_label: str) -> List[Signal]:
    etype = EMAP.get(
        analysis.get("primary_event_type", "motion_detection"),
        EventType.MOTION_DETECTION,
    )
    conf = float(analysis.get("confidence", 40))

    # Boost confidence for confirmed audio threats
    if analysis.get("has_explosion") or analysis.get("has_fire_audio"):
        conf = min(100, conf + 25)
        etype = EventType.EXPLOSION if analysis.get("has_explosion") else EventType.FIRE
    if analysis.get("has_weapon_audio"):
        conf = min(100, conf + 20)
        etype = EventType.GUNSHOT_AUDIO
    if analysis.get("has_distress_signals"):
        conf = min(100, conf + 10)

    return [
        Signal(
            type=etype,
            confidence=conf,
            timestamp=datetime.now(),
            location=source_label,
            metadata={
                "scene_summary": analysis.get("scene_summary", ""),
                "detected_sounds": analysis.get("detected_sounds", []),
                "transcript": analysis.get("transcript_text", ""),
                "distress_keywords": analysis.get("distress_keywords", []),
                "has_distress": analysis.get("has_distress_signals", False),
                "has_weapon_audio": analysis.get("has_weapon_audio", False),
                "has_explosion": analysis.get("has_explosion", False),
                "has_fire_audio": analysis.get("has_fire_audio", False),
                "is_panic_call": analysis.get("is_panic_call", False),
                "threat_rationale": analysis.get("threat_rationale", ""),
                # Signal fusion metadata
                "frequency": "high" if analysis.get("has_weapon_audio") else "low",
                "duration": "brief" if analysis.get("has_weapon_audio") else "long",
            },
        )
    ]


def make_context(analysis: Dict) -> SecurityContext:
    return SecurityContext(
        zone_type=analysis.get("zone_guess", "high_security"),
        time_of_day=datetime.now().strftime("%H:%M"),
        authorized_personnel=[],
        metadata={"source": "audio_pipeline"},
    )


# ── Step 7: Officer briefing ─────────────────────────────────────────────────


def officer_briefing(
    analysis: Dict,
    transcript: Dict,
    threat: ThreatLevel,
    action: str,
    visual_cue: str,
    temporal: Dict,
) -> str:
    prompt = f"""You are a Certis Security command centre advisor.
Write a 3-4 sentence officer briefing. Be direct. No bullet points.
Cover: what was heard, confidence, transcript content, and immediate action.

Scene: {analysis.get('scene_summary')}
Detected sounds: {', '.join(analysis.get('detected_sounds', []))}
Threat: {threat.value.upper()} | Action: {action}
Weapon audio: {analysis.get('has_weapon_audio')}
Explosion: {analysis.get('has_explosion')}
Fire audio: {analysis.get('has_fire_audio')}
Distress signals: {analysis.get('has_distress_signals')}
Panic call: {analysis.get('is_panic_call')}
Whisper transcript: "{transcript.get('text', '')[:200]}"
Distress keywords: {transcript.get('distress_keywords', [])}
Rationale: {analysis.get('threat_rationale', '')}
Notes: {analysis.get('notes', '')}

Briefing:"""
    try:
        r = _post(
            "/api/generate",
            {
                "model": TEXT_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3},
            },
        )
        return r.get("response", "").strip()
    except Exception:
        return (
            f"{action}\n\n"
            f"Confidence: {analysis.get('confidence', 40)}%\n\n"
            f"{analysis.get('scene_summary', 'Audio incident detected')}"
        )


# ── Main analysis function ───────────────────────────────────────────────────


def analyse_audio(
    audio_path: str, verbose: bool = True, enable_tts: bool = True
) -> Dict:
    print(f"\n{'='*60}\nCERTIS SECURITY — AUDIO ANALYSIS PIPELINE\n{'='*60}")
    print(f"Input: {audio_path}")

    if not ollama_running():
        print("ERROR: Ollama not running. Start with: ollama serve")
        sys.exit(1)

    # ── [1/5] Load audio ─────────────────────────────────────────────────────
    print("\n[1/5] Loading audio...")
    y, sr = load_audio_file(audio_path)

    # ── [2/5] Acoustic features ──────────────────────────────────────────────
    print("\n[2/5] Extracting acoustic features...")
    feat = extract_audio_features(y, sr)
    rule_label, rule_conf = rule_classify(feat)

    if verbose:
        print(f"  Duration   : {feat.get('duration_s')}s")
        print(
            f"  RMS mean   : {feat.get('rms_mean')}  peak ratio: {feat.get('peak_ratio')}"
        )
        print(
            f"  ZCR mean   : {feat.get('zcr_mean')}  HF ratio  : {feat.get('hf_ratio')}"
        )
        print(
            f"  Onsets     : {feat.get('onset_count')} ({feat.get('onset_density')}/s)"
        )
        print(
            f"  Impulsive  : {feat.get('is_impulsive')}  Sustained: {feat.get('is_sustained')}  "
            f"Crackling: {feat.get('is_crackling')}"
        )
        print(f"  Pre-class  : {rule_label} ({rule_conf}%)")

    # ── [3/5] Speech transcription ───────────────────────────────────────────
    print("\n[3/5] Whisper transcription...")
    transcript = transcribe_audio(audio_path)
    if verbose:
        print(f"  Text       : \"{transcript.get('text', '')[:100]}\"")
        print(f"  Distress kw: {transcript.get('distress_keywords', [])}")

    # ── [4/5] Ollama reasoning ───────────────────────────────────────────────
    print("\n[4/5] Ollama audio reasoning...")
    analysis = ollama_audio_reasoning(feat, transcript, rule_label, rule_conf)
    # Attach transcript to analysis for briefing step
    analysis["transcript_text"] = transcript.get("text", "")
    analysis["distress_keywords"] = transcript.get("distress_keywords", [])

    if verbose:
        print(
            f"  Event type : {analysis.get('primary_event_type')} ({analysis.get('confidence')}%)"
        )
        print(f"  Summary    : {analysis.get('scene_summary')}")
        print(
            f"  Weapon     : {analysis.get('has_weapon_audio')}  "
            f"Explosion: {analysis.get('has_explosion')}  "
            f"Fire: {analysis.get('has_fire_audio')}  "
            f"Panic: {analysis.get('is_panic_call')}"
        )
        print(f"  Zone       : {analysis.get('zone_guess')}")

    # ── SecurityAgent ─────────────────────────────────────────────────────────
    signals = make_signals(analysis, Path(audio_path).stem)
    context = make_context(analysis)
    agent = SecurityAgent()

    threat = agent.analyze_signal_fusion(signals, context)
    temporal = agent.temporal_reasoning(signals, context)
    avg_conf = sum(s.confidence for s in signals) / len(signals)
    rec = agent.proportionality_encoding(threat, avg_conf, context)
    attack = agent.detect_sensor_attack(signals)

    if verbose:
        print(f"\n  Threat   : {threat.value.upper()}  |  {rec.visual_cue}")
        print(f"  Action   : {rec.action}")
        print(
            f"  Urgency  : {rec.urgency}  |  Human needed: {rec.requires_human_approval}"
        )
        print(
            f"  Alt      : {rec.confidence.alternative} ({rec.confidence.alternative_confidence:.0f}%)"
        )
        print(f"  Window   : {temporal['window_minutes']} min")
        if attack:
            print(f"  ATTACK   : {attack}")

    # ── [5/5] Officer briefing ────────────────────────────────────────────────
    print("\n[5/5] Generating officer briefing...")
    briefing = officer_briefing(
        analysis, transcript, threat, rec.action, rec.visual_cue, temporal
    )

    print(f"\n{'='*60}\nOFFICER BRIEFING — AUDIO\n{'='*60}")
    print(f"\n{rec.visual_cue}  {rec.action}\n")
    print(briefing)

    if enable_tts:
        print("\n🔊 Speaking alert...")
        speak_alert(threat, rec.action, briefing)
        if rec.requires_human_approval:
            speak("Human approval required for this action.")
        if attack:
            speak(f"Sensor attack warning. {attack}")

    if rec.requires_human_approval:
        print("\n  ⚠  HUMAN APPROVAL REQUIRED")
    if attack:
        print(f"\n  🔴 SENSOR ATTACK: {attack}")

    print(f"\n{'='*60}\n")

    result = {
        "audio_path": audio_path,
        "timestamp": datetime.now().isoformat(),
        "acoustic_features": feat,
        "rule_pre_class": {"label": rule_label, "confidence": rule_conf},
        "whisper": transcript,
        "ollama_analysis": analysis,
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
        "officer_briefing": briefing,
    }

    out = Path(audio_path).stem + "_audio_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"Saved: {out}")
    return result


# ── Live mic mode ────────────────────────────────────────────────────────────


def analyse_mic_live(
    chunk_duration: int = MIC_DURATION, enable_tts: bool = True, verbose: bool = True
):
    """
    Continuously capture audio from the default microphone,
    analyse each chunk, and print/speak the result.
    Press Ctrl-C to stop.
    """
    import tempfile
    import soundfile as sf

    if not SD_OK:
        print("ERROR: sounddevice not installed. Run: pip install sounddevice")
        sys.exit(1)
    if not ollama_running():
        print("ERROR: Ollama not running. Start with: ollama serve")
        sys.exit(1)

    print(f"\n{'='*60}\nCERTIS SECURITY — LIVE MIC PIPELINE\n{'='*60}")
    print(f"Chunk size: {chunk_duration}s | Press Ctrl-C to stop\n")

    chunk_num = 0
    try:
        while True:
            chunk_num += 1
            print(f"\n--- Chunk #{chunk_num} ---")
            y, sr = capture_mic_chunk(chunk_duration)

            # Save to temp WAV so Whisper can read it
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp_path = tmp.name
            sf.write(tmp_path, y, sr)

            try:
                analyse_audio(tmp_path, verbose=verbose, enable_tts=enable_tts)
            finally:
                os.unlink(tmp_path)

    except KeyboardInterrupt:
        print("\n\nLive mic mode stopped.")


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    enable_tts = "--no-tts" not in sys.argv
    verbose = "--quiet" not in sys.argv

    if "--mic" in sys.argv:
        # Live mic mode
        duration = MIC_DURATION
        for arg in sys.argv:
            if arg.startswith("--duration="):
                duration = int(arg.split("=")[1])
        analyse_mic_live(
            chunk_duration=duration, enable_tts=enable_tts, verbose=verbose
        )

    else:
        # File mode
        path = next((a for a in sys.argv[1:] if not a.startswith("--")), None)
        if not path:
            path = input("Audio file path: ").strip()
        if not os.path.exists(path):
            print(f"File not found: {path}")
            sys.exit(1)
        analyse_audio(path, verbose=verbose, enable_tts=enable_tts)
