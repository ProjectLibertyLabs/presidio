"""Custom recognizer for the OpenAI privacy-filter ONNX model."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from presidio_analyzer.analysis_explanation import AnalysisExplanation
from presidio_analyzer.local_recognizer import LocalRecognizer
from presidio_analyzer.nlp_engine import NlpArtifacts
from presidio_analyzer.recognizer_result import RecognizerResult

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover - import guard
    ort = None

try:
    from transformers import PreTrainedTokenizerFast
except ImportError:  # pragma: no cover - import guard
    PreTrainedTokenizerFast = None

try:
    import phonenumbers
    from phonenumbers import Leniency as _PhoneLeniency
except ImportError:  # pragma: no cover - phonenumbers is a hard dep of presidio-analyzer
    phonenumbers = None
    _PhoneLeniency = None


DEFAULT_MODEL_DIR = "/models/privacy-filter"
DEFAULT_ONNX_MODEL_FILE = "model_q4.onnx"

# Default lemma cues fed to LemmaContextAwareEnhancer for confidence boosting
# on DATE_TIME (DOB) and SECRET results emitted by the privacy-filter model.
# The enhancer matches against spaCy lemmas (substring, case-insensitive), so
# entries here must be lemma forms — e.g. "bear" catches "born"/"bears"/"bore",
# while "born" alone never matches anything because the lemma is "bear".
DEFAULT_CONTEXT_CUES: Tuple[str, ...] = (
    # DOB cues
    "dob",
    "birth",  # birthday, birthdate, birth
    "bear",   # born, bears, bore (lemma of "born")
    # Secret cues
    "password",
    "passphrase",
    "passwd",
    "secret",
    "token",
    "credential",
    "api",
    "key",
)

# Window (in characters) on either side of a detection used to look for context
# cues that promote a generic `private_date` span to a `dob` span.
ENTITY_CONTEXT_WINDOW = 50
DOB_CONTEXT_CUES: Tuple[str, ...] = (
    "dob",
    "date of birth",
    "birth date",
    "born",
)

# Regions tried, in order, when validating a `private_phone` span via the
# `phonenumbers` library. The privacy-filter model frequently mislabels credit
# cards, SSNs, IP addresses, and other long numeric IDs as phones; running the
# span through `PhoneNumberMatcher(..., Leniency.VALID)` filters those out
# while keeping real numbers, and lets us trim the span to just the phone
# portion (e.g. dropping a leading "Reginald " that the model swept up).
PHONE_VALIDATION_REGIONS: Tuple[str, ...] = (
    "US", "GB", "CA", "IN", "BR", "DE", "IL", "AU", "FR", "MX",
)
PHONE_POSITIVE_CONTEXT_CUES: Tuple[str, ...] = (
    "phone",
    "phone number",
    "call",
    "contact",
    "telephone",
    "mobile",
    "fax",
    "fax number",
)
PHONE_NEGATIVE_CONTEXT_CUES: Tuple[str, ...] = (
    "medical record",
    "medical record number",
    "record number",
    "policy number",
    "beneficiary number",
    "health plan beneficiary",
    "account number",
    "customer id",
    "transaction id",
    "routing",
    "biometric",
    "pin",
    "otp",
)

# Min character length below which a SECRET span is treated as noise unless a
# strong secret cue appears within SECRET_CONTEXT_WINDOW characters before it.
SECRET_MIN_LENGTH = 3
SECRET_CONTEXT_WINDOW = 50
STRONG_SECRET_CUES: Tuple[str, ...] = (
    "wifi password",
    "password",
    "passphrase",
    "passwd",
    "secret",
    "token",
    "api key",
    "access key",
    "private key",
)


@dataclass(slots=True)
class _OpenSpan:
    label: str
    start: int
    end: int
    last_index: int
    scores: List[float] = field(default_factory=list)


@dataclass(slots=True)
class _Detection:
    label: str
    score: float
    start: int
    end: int


def _parse_entity_tag(entity: str) -> Optional[Tuple[str, str]]:
    if entity == "O":
        return None
    if "-" not in entity:
        return "S", entity
    prefix, label = entity.split("-", 1)
    return prefix, label


def _trim_span(text: str, start: int, end: int) -> Tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _finalize_span(text: str, span: _OpenSpan) -> Optional[_Detection]:
    start, end = _trim_span(text, span.start, span.end)
    if start >= end:
        return None
    score = sum(span.scores) / len(span.scores)
    return _Detection(label=span.label, score=score, start=start, end=end)


def _start_span(label: str, start: int, end: int, index: int, score: float) -> _OpenSpan:
    return _OpenSpan(label=label, start=start, end=end, last_index=index, scores=[score])


def _merge_raw_detections(
    text: str, raw_detections: List[Dict[str, Any]]
) -> List[_Detection]:
    detections: List[_Detection] = []
    current: Optional[_OpenSpan] = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        detection = _finalize_span(text, current)
        if detection is not None:
            detections.append(detection)
        current = None

    for item in raw_detections:
        parsed = _parse_entity_tag(str(item["entity"]))
        if parsed is None:
            flush()
            continue

        prefix, label = parsed
        start = int(item["start"])
        end = int(item["end"])
        index = int(item["index"])
        score = float(item["score"])

        if prefix == "S":
            flush()
            current = _start_span(label, start, end, index, score)
            flush()
            continue

        if prefix == "B":
            flush()
            current = _start_span(label, start, end, index, score)
            continue

        if (
            current is not None
            and current.label == label
            and index == current.last_index + 1
        ):
            current.end = end
            current.last_index = index
            current.scores.append(score)
        else:
            flush()
            current = _start_span(label, start, end, index, score)

        if prefix == "E":
            flush()

    flush()
    return detections


def _context_window(
    text: str, start: int, end: int, window: int = ENTITY_CONTEXT_WINDOW
) -> str:
    window_start = max(0, start - window)
    window_end = min(len(text), end + window)
    before = text[window_start:start]
    after = text[end:window_end]
    return f"{before} {after}".lower()


def _has_any_context_cue(context: str, cues: Tuple[str, ...]) -> bool:
    return any(cue in context for cue in cues)


def _phone_context_flags(text: str, start: int, end: int) -> Tuple[bool, bool]:
    context = _context_window(text, start, end)
    has_positive = _has_any_context_cue(context, PHONE_POSITIVE_CONTEXT_CUES)
    has_negative = _has_any_context_cue(context, PHONE_NEGATIVE_CONTEXT_CUES)
    return has_positive, has_negative


def _promote_dob(text: str, detection: _Detection) -> _Detection:
    if detection.label != "private_date":
        return detection
    context = _context_window(text, detection.start, detection.end)
    if not _has_any_context_cue(context, DOB_CONTEXT_CUES):
        return detection
    return _Detection(
        label="dob",
        score=detection.score,
        start=detection.start,
        end=detection.end,
    )


def _validate_and_trim_phone(text: str, detection: _Detection) -> Optional[_Detection]:
    """Validate a `private_phone` span via `phonenumbers` and tighten its span.

    Returns a `_Detection` whose offsets cover only the phonenumbers match
    (so e.g. "Reginald 616-938-4790" becomes "616-938-4790"), or `None` if
    no valid phone is found in any of `PHONE_VALIDATION_REGIONS`. Non-phone
    detections pass through unchanged.
    """
    if detection.label != "private_phone":
        return detection
    if phonenumbers is None or _PhoneLeniency is None:
        return detection
    span_text = text[detection.start:detection.end]
    if not span_text.strip():
        return None
    for region in PHONE_VALIDATION_REGIONS:
        matcher = phonenumbers.PhoneNumberMatcher(
            span_text, region, leniency=_PhoneLeniency.VALID
        )
        for match in matcher:
            new_start = detection.start + match.start
            new_end = detection.start + match.end
            if new_end <= new_start:
                continue
            return _Detection(
                label=detection.label,
                score=detection.score,
                start=new_start,
                end=new_end,
            )
    return None


def _filter_phone_context(text: str, detection: _Detection) -> Optional[_Detection]:
    if detection.label != "private_phone":
        return detection
    has_positive_context, has_negative_context = _phone_context_flags(
        text,
        detection.start,
        detection.end,
    )
    if has_negative_context and not has_positive_context:
        return None
    return detection


def _build_transition_tables(
    id2label: Dict[int, str],
) -> Tuple[Dict[int, List[int]], List[int], List[int]]:
    label_ids = sorted(id2label)

    def can_start(label: str) -> bool:
        if label == "O":
            return True
        prefix, _ = label.split("-", 1)
        return prefix in {"B", "S"}

    def can_end(label: str) -> bool:
        if label == "O":
            return True
        prefix, _ = label.split("-", 1)
        return prefix in {"E", "S"}

    def is_allowed(prev_label: str, next_label: str) -> bool:
        if prev_label == "O":
            if next_label == "O":
                return True
            prefix, _ = next_label.split("-", 1)
            return prefix in {"B", "S"}

        prev_prefix, prev_base = prev_label.split("-", 1)
        if next_label == "O":
            return prev_prefix in {"E", "S"}

        next_prefix, next_base = next_label.split("-", 1)
        if prev_prefix in {"B", "I"}:
            return next_base == prev_base and next_prefix in {"I", "E"}
        if prev_prefix in {"E", "S"}:
            return next_prefix in {"B", "S"}
        return False

    allowed_prev_ids: Dict[int, List[int]] = {}
    start_ids = [lid for lid, label in id2label.items() if can_start(label)]
    end_ids = [lid for lid, label in id2label.items() if can_end(label)]

    for next_id in label_ids:
        next_label = id2label[next_id]
        allowed_prev_ids[next_id] = [
            prev_id for prev_id in label_ids if is_allowed(id2label[prev_id], next_label)
        ]
    return allowed_prev_ids, start_ids, end_ids


def _decode_bioes_viterbi(logits: np.ndarray, id2label: Dict[int, str]) -> List[int]:
    if logits.ndim != 2:
        raise ValueError(f"Expected logits with shape [tokens, labels], got {logits.shape}")

    token_count, _ = logits.shape
    if token_count == 0:
        return []

    allowed_prev_ids, start_ids, end_ids = _build_transition_tables(id2label)
    neg_inf = np.float32(-1e30)
    scores = np.full(logits.shape, neg_inf, dtype=np.float32)
    backpointers = np.full(logits.shape, -1, dtype=np.int32)

    for label_id in start_ids:
        scores[0, label_id] = logits[0, label_id]

    for token_index in range(1, token_count):
        for label_id in range(logits.shape[1]):
            prev_ids = allowed_prev_ids[label_id]
            if not prev_ids:
                continue
            prev_scores = scores[token_index - 1, prev_ids]
            best_prev_offset = int(np.argmax(prev_scores))
            best_prev_id = prev_ids[best_prev_offset]
            best_prev_score = prev_scores[best_prev_offset]
            if best_prev_score <= neg_inf / 2:
                continue
            scores[token_index, label_id] = best_prev_score + logits[token_index, label_id]
            backpointers[token_index, label_id] = best_prev_id

    last_scores = scores[-1, end_ids]
    best_last_id = end_ids[int(np.argmax(last_scores))]

    if last_scores.max() <= neg_inf / 2:
        return logits.argmax(axis=-1).astype(int).tolist()

    path = [best_last_id]
    for token_index in range(token_count - 1, 0, -1):
        previous = int(backpointers[token_index, path[-1]])
        if previous < 0:
            return logits.argmax(axis=-1).astype(int).tolist()
        path.append(previous)
    path.reverse()
    return path


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=-1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=-1, keepdims=True)


class PrivacyFilterONNXRecognizer(LocalRecognizer):
    """Recognizer wrapping the OpenAI privacy-filter quantized ONNX model.

    The model and its tokenizer files (config.json, tokenizer.json,
    tokenizer_config.json, model_q4.onnx, model_q4.onnx_data) are loaded from a
    directory provided by the YAML config, the ``PRIVACY_FILTER_MODEL_PATH``
    env var, or the default ``/models/privacy-filter``. The model is **not**
    packaged with the analyzer — it is mounted as a volume at runtime.

    Confidence boosts based on DOB / secret context are delegated to the
    engine-level ``LemmaContextAwareEnhancer`` via ``self.context``. The only
    bespoke postprocessing is dropping very short SECRET spans when they are
    not flanked by a strong secret cue (the model emits noisy 1-2 char
    fragments inside arbitrary tokens).
    """

    # `private_date` is intentionally absent: the model emits `private_date` for
    # every date-like span (appointments, expirations, etc.), but only spans
    # promoted to `dob` by `_promote_dob` (when a DOB cue sits within
    # `ENTITY_CONTEXT_WINDOW` chars) are surfaced as a Presidio entity. This
    # mirrors the standalone privacy-filter HTTP service, which only maps `dob`
    # to a public entity type and silently drops generic dates.
    DEFAULT_ENTITY_MAPPING: Dict[str, str] = {
        "private_person": "PERSON",
        "private_phone": "PHONE_NUMBER",
        "private_email": "EMAIL_ADDRESS",
        "private_address": "LOCATION",
        "dob": "DOB",
        "secret": "SECRET",
        "account_number": "US_SSN",
        "credit_card": "CREDIT_CARD",
    }

    _MODEL_CACHE: Dict[Tuple[str, Tuple[str, ...]], Tuple[Any, Any, Dict[int, str]]] = {}

    def __init__(
        self,
        supported_language: str = "en",
        name: str = "PrivacyFilterRecognizer",
        version: str = "0.0.1",
        model_dir: Optional[str] = None,
        providers: Optional[List[str]] = None,
        entity_mapping: Optional[Dict[str, str]] = None,
        target_entities: Optional[List[str]] = None,
        score_threshold: float = 0.0,
        context: Optional[List[str]] = None,
        **kwargs,
    ):
        self.entity_mapping = dict(entity_mapping) if entity_mapping else dict(
            self.DEFAULT_ENTITY_MAPPING
        )
        self.target_entities = target_entities or []
        self.score_threshold = score_threshold

        env_model_dir = os.environ.get("PRIVACY_FILTER_MODEL_PATH")
        self.model_dir = str(model_dir or env_model_dir or DEFAULT_MODEL_DIR)
        self.providers = list(providers) if providers else None

        self._session = None
        self._tokenizer = None
        self._id2label: Dict[int, str] = {}

        supported_entities = sorted({entity for entity in self.entity_mapping.values()})
        super().__init__(
            supported_entities=supported_entities,
            name=name,
            supported_language=supported_language,
            version=version,
            context=list(context) if context else list(DEFAULT_CONTEXT_CUES),
        )

    @staticmethod
    def _default_providers() -> List[str]:
        if ort is None:
            return []
        available = set(ort.get_available_providers())
        preferred = ["CPUExecutionProvider"]
        return [provider for provider in preferred if provider in available] or list(
            available
        )

    @classmethod
    def _cache_key(
        cls, model_dir: str, providers: List[str]
    ) -> Tuple[str, Tuple[str, ...]]:
        return (str(Path(model_dir).resolve()), tuple(providers))

    def load(self) -> None:
        """Load and cache the ONNX session + tokenizer."""
        if ort is None:
            raise ImportError(
                "onnxruntime is required for PrivacyFilterONNXRecognizer. "
                "Install with the 'gliner' poetry extra."
            )
        if PreTrainedTokenizerFast is None:
            raise ImportError(
                "transformers is required for PrivacyFilterONNXRecognizer. "
                "Install with the 'gliner' poetry extra."
            )

        providers = self.providers or self._default_providers()
        cache_key = self._cache_key(self.model_dir, providers)
        cached = self._MODEL_CACHE.get(cache_key)
        if cached is not None:
            self._session, self._tokenizer, self._id2label = cached
            return

        model_path = Path(self.model_dir)
        onnx_path = model_path / DEFAULT_ONNX_MODEL_FILE
        config_path = model_path / "config.json"
        tokenizer_path = model_path / "tokenizer.json"
        if not onnx_path.exists():
            raise FileNotFoundError(
                f"ONNX model file not found at {onnx_path}. Set "
                "PRIVACY_FILTER_MODEL_PATH to the directory containing "
                "model_q4.onnx, tokenizer.json, config.json, etc., or run "
                "scripts/download_privacy_filter_model.sh."
            )
        if not config_path.exists():
            raise FileNotFoundError(
                f"config.json not found at {config_path}; expected to live "
                "alongside model_q4.onnx."
            )
        if not tokenizer_path.exists():
            raise FileNotFoundError(
                f"tokenizer.json not found at {tokenizer_path}; expected to "
                "live alongside model_q4.onnx."
            )

        # Read config.json directly: privacy-filter uses a custom model_type
        # ("openai_privacy_filter") that AutoConfig.from_pretrained refuses to
        # load. We only need id2label, so json.load is sufficient.
        with config_path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
        raw_id2label = config.get("id2label") or {}
        if not raw_id2label:
            raise ValueError(
                f"config.json at {config_path} is missing 'id2label'."
            )
        id2label = {int(key): value for key, value in raw_id2label.items()}

        # Build the tokenizer directly from tokenizer.json. tokenizer_config.json
        # references a custom tokenizer class (TokenizersBackend) that the
        # AutoTokenizer registry doesn't know; PreTrainedTokenizerFast wraps any
        # tokenizers-library Tokenizer and gives us return_offsets_mapping +
        # return_special_tokens_mask, which is everything analyze() needs.
        tokenizer_kwargs: Dict[str, Any] = {"tokenizer_file": str(tokenizer_path)}
        tokenizer_config_path = model_path / "tokenizer_config.json"
        if tokenizer_config_path.exists():
            with tokenizer_config_path.open("r", encoding="utf-8") as fh:
                raw_tokenizer_config = json.load(fh)
            for key in (
                "model_max_length",
                "padding_side",
                "truncation_side",
                "bos_token",
                "eos_token",
                "unk_token",
                "sep_token",
                "pad_token",
                "cls_token",
                "mask_token",
                "additional_special_tokens",
            ):
                if key in raw_tokenizer_config:
                    tokenizer_kwargs[key] = raw_tokenizer_config[key]
        tokenizer = PreTrainedTokenizerFast(**tokenizer_kwargs)

        # Cap ONNX thread fan-out. Defaults to physical core count, which on a
        # multi-threaded gunicorn worker (THREADS=4) explodes to 4×N threads
        # all fighting for the same cores; on Docker Desktop this surfaces as
        # 100s+ p99 latency and "Server disconnected" on the client. Override
        # with ONNX_INTRA_OP_NUM_THREADS / ONNX_INTER_OP_NUM_THREADS if needed.
        sess_options = ort.SessionOptions()
        intra = int(os.environ.get("ONNX_INTRA_OP_NUM_THREADS", "2"))
        inter = int(os.environ.get("ONNX_INTER_OP_NUM_THREADS", "1"))
        sess_options.intra_op_num_threads = intra
        sess_options.inter_op_num_threads = inter
        session = ort.InferenceSession(
            str(onnx_path),
            sess_options=sess_options,
            providers=providers,
        )

        self._session = session
        self._tokenizer = tokenizer
        self._id2label = id2label
        self._MODEL_CACHE[cache_key] = (session, tokenizer, id2label)

    def _session_inputs(
        self, input_ids: np.ndarray, attention_mask: np.ndarray
    ) -> Dict[str, np.ndarray]:
        input_names = {item.name for item in self._session.get_inputs()}
        inputs: Dict[str, np.ndarray] = {}
        if "input_ids" in input_names:
            inputs["input_ids"] = input_ids
        if "attention_mask" in input_names:
            inputs["attention_mask"] = attention_mask
        if "position_ids" in input_names:
            inputs["position_ids"] = np.arange(input_ids.shape[1], dtype=np.int64)[None, :]

        missing = input_names.difference(inputs)
        if missing:
            raise RuntimeError(
                f"Unsupported ONNX input names: {', '.join(sorted(missing))}"
            )
        return inputs

    def _is_strong_secret(self, text: str, start: int, end: int) -> bool:
        if (end - start) >= SECRET_MIN_LENGTH:
            return True
        window_start = max(0, start - SECRET_CONTEXT_WINDOW)
        context = text[window_start:start].lower()
        return any(cue in context for cue in STRONG_SECRET_CUES)

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional[NlpArtifacts] = None,
    ) -> List[RecognizerResult]:
        if not text:
            return []

        encoded = self._tokenizer(
            text,
            return_offsets_mapping=True,
            return_special_tokens_mask=True,
            truncation=True,
            return_tensors="np",
        )
        input_ids = encoded["input_ids"].astype(np.int64, copy=False)
        attention_mask = encoded["attention_mask"].astype(np.int64, copy=False)

        output_name = self._session.get_outputs()[0].name
        logits = self._session.run(
            [output_name],
            self._session_inputs(input_ids=input_ids, attention_mask=attention_mask),
        )[0][0]

        probabilities = _softmax(logits)
        best_label_ids = _decode_bioes_viterbi(logits, self._id2label)

        offsets = encoded["offset_mapping"][0].tolist()
        special_tokens_mask = encoded["special_tokens_mask"][0].tolist()

        raw_detections: List[Dict[str, Any]] = []
        for index, (label_id, offset, is_special) in enumerate(
            zip(best_label_ids, offsets, special_tokens_mask, strict=False)
        ):
            if is_special:
                continue
            start, end = int(offset[0]), int(offset[1])
            if start == end:
                continue
            raw_detections.append(
                {
                    "entity": self._id2label[int(label_id)],
                    "score": float(probabilities[index, int(label_id)]),
                    "index": index,
                    "start": start,
                    "end": end,
                }
            )

        detections = _merge_raw_detections(text, raw_detections)
        detections = [_promote_dob(text, det) for det in detections]
        filtered_detections = []
        for det in detections:
            trimmed = _validate_and_trim_phone(text, det)
            if trimmed is None:
                continue
            trimmed = _filter_phone_context(text, trimmed)
            if trimmed is not None:
                filtered_detections.append(trimmed)
        detections = filtered_detections

        requested = set(entities or [])
        target = set(self.target_entities or [])

        results: List[RecognizerResult] = []
        for det in detections:
            if det.score < self.score_threshold:
                continue
            presidio_entity = self.entity_mapping.get(det.label)
            if presidio_entity is None:
                continue
            if requested and presidio_entity not in requested:
                continue
            if target and presidio_entity not in target:
                continue
            if presidio_entity == "SECRET" and not self._is_strong_secret(
                text, det.start, det.end
            ):
                continue

            results.append(
                RecognizerResult(
                    entity_type=presidio_entity,
                    start=det.start,
                    end=det.end,
                    score=det.score,
                    analysis_explanation=AnalysisExplanation(
                        recognizer=self.name,
                        original_score=det.score,
                        textual_explanation=(
                            f"Identified as {presidio_entity} by Privacy Filter "
                            f"ONNX (label={det.label})"
                        ),
                    ),
                )
            )

        return results
