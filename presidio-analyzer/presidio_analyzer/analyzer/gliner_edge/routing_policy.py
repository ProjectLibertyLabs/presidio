"""Routing policy helpers for multi-recognizer GLiNER pipelines."""

from __future__ import annotations

import copy
from typing import Dict, Iterable, List, Tuple

import regex as re

LOCATION_ENTITY = "LOCATION"
PHONE_ENTITY = "PHONE_NUMBER"
CREDIT_CARD_ENTITY = "CREDIT_CARD"
SSN_ENTITY = "US_SSN"
EMAIL_ENTITY = "EMAIL_ADDRESS"
PHONE_DIGIT_OVERLAP_ENTITIES = (SSN_ENTITY, CREDIT_CARD_ENTITY)
SAME_CATEGORY_SCORE_CLOSE_THRESHOLD = 0.1
EMPTY_SET = frozenset()
STREET_SUFFIXES = frozenset(
    {
        "alley",
        "aly",
        "ave",
        "avenue",
        "blvd",
        "boulevard",
        "cir",
        "circle",
        "court",
        "ct",
        "drive",
        "dr",
        "highway",
        "hwy",
        "lane",
        "ln",
        "loop",
        "parkway",
        "pkwy",
        "place",
        "pl",
        "rd",
        "road",
        "route",
        "rte",
        "run",
        "sq",
        "square",
        "st",
        "street",
        "suite",
        "ter",
        "terrace",
        "tk",
        "track",
        "trace",
        "trl",
        "trail",
        "unit",
        "way",
    }
)
UNIT_TOKENS = frozenset({"apt", "apartment", "unit", "suite", "ste", "floor", "fl"})
COMPACT_CODE_RE = re.compile(r"^[A-Za-z]{1,4}\d{2,}$")
MAC_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
NUMBER_ONLY_RE = re.compile(r"^\d+$")
ZIP_ONLY_RE = re.compile(r"^\d{5}(?:-\d{4})?$")
LEADING_ADDRESS_NUMBER_RE = re.compile(
    r"^\s*(?:(?:apt|apartment|unit|suite|ste|floor|fl)\.?\s+\w+\s*,\s*)?\d+[A-Za-z]?\b",
    re.IGNORECASE,
)
LEADING_DECIMAL_RE = re.compile(r"^\s*-?\d+\.\d+\b")
LEADING_SEPARATORS_RE = re.compile(r"^[\s,;:.()-]+")
TRAILING_SEPARATORS_RE = re.compile(r"[\s,;:.()-]+$")
CONNECTOR_SPLIT_RE = re.compile(r"\s+\b(?:in|at)\b\s+", re.IGNORECASE)
SEPARATOR_SPLIT_RE = re.compile(r"[,;\n]+")
COORDINATE_RE = re.compile(
    r"""
    (?:
        \b-?\d{1,3}\.\d+\s*[NS]?\s*,\s*-?\d{1,3}\.\d+\s*[EW]?\b
        |
        ^\(?\s*-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+\s*\)?\.?$
        |
        \bcoordinate\s+-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def result_dedupe_key(text: str, result) -> Tuple[str, int, int, str]:
    """Build a stable dedupe key from entity type, span, and normalized text."""
    normalized = " ".join(text[result.start : result.end].split()).lower()
    return result.entity_type, result.start, result.end, normalized


def _normalize_text(value: str) -> str:
    return " ".join(value.split()).strip().lower()


def _normalize_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _get_recognizer_name(result) -> str:
    metadata = getattr(result, "recognition_metadata", None) or {}
    if metadata.get("recognizer_name"):
        return metadata["recognizer_name"]
    explanation = getattr(result, "analysis_explanation", None)
    return explanation.recognizer if explanation else ""


def _slice_text(text: str, start: int, end: int) -> str:
    return text[start:end]


def _trim_separators(text: str, start: int, end: int) -> Tuple[int, int]:
    segment = text[start:end]
    leading = LEADING_SEPARATORS_RE.match(segment)
    if leading:
        start += leading.end()
    segment = text[start:end]
    trailing = TRAILING_SEPARATORS_RE.search(segment)
    if trailing and trailing.start() < len(segment):
        end = start + trailing.start()
    return start, end


def _contains_early_house_number(value: str) -> bool:
    return bool(LEADING_ADDRESS_NUMBER_RE.search(value))


def _has_street_marker(value: str) -> bool:
    tokens = re.findall(r"[A-Za-z0-9]+", value.lower())
    return any(token in STREET_SUFFIXES or token in UNIT_TOKENS for token in tokens)


def _looks_like_coordinate(value: str) -> bool:
    return bool(COORDINATE_RE.search(value.strip()))


def _is_address_candidate(value: str) -> bool:
    normalized = _normalize_text(value)
    if not normalized or normalized in {"n/a", "na"}:
        return False
    if MAC_ADDRESS_RE.fullmatch(value.strip()):
        return False
    if COMPACT_CODE_RE.fullmatch(value.strip()):
        return False
    if ZIP_ONLY_RE.fullmatch(value.strip()):
        return False
    if NUMBER_ONLY_RE.fullmatch(value.strip()):
        return False
    if LEADING_DECIMAL_RE.search(value):
        return False
    if _looks_like_coordinate(value):
        return False

    if "po box" in normalized or "p.o. box" in normalized:
        return True

    if not _contains_early_house_number(value):
        return False

    if _has_street_marker(value):
        return True

    alpha_tokens = re.findall(r"[A-Za-z]+", value)
    return len(alpha_tokens) >= 1


def _candidate_prefix_offsets(
    segment_text: str, splitter: re.Pattern
) -> Iterable[Tuple[int, int]]:
    for match in splitter.finditer(segment_text):
        prefix_end = match.start()
        if prefix_end <= 0:
            continue
        yield 0, prefix_end


def _trim_location_result_to_address(text: str, result):
    start, end = _trim_separators(text, result.start, result.end)
    if start >= end:
        return None

    span_text = _slice_text(text, start, end)
    candidates = [(start, end)]

    for local_start, local_end in _candidate_prefix_offsets(span_text, CONNECTOR_SPLIT_RE):
        candidates.append((start + local_start, start + local_end))
    for local_start, local_end in _candidate_prefix_offsets(span_text, SEPARATOR_SPLIT_RE):
        candidates.append((start + local_start, start + local_end))

    for candidate_start, candidate_end in candidates[1:]:
        candidate_start, candidate_end = _trim_separators(
            text, candidate_start, candidate_end
        )
        if candidate_start >= candidate_end:
            continue
        if _is_address_candidate(_slice_text(text, candidate_start, candidate_end)):
            start, end = candidate_start, candidate_end
            break

    candidate_text = _slice_text(text, start, end)
    if not _is_address_candidate(candidate_text):
        return None

    cloned = copy.copy(result)
    cloned.start = start
    cloned.end = end
    return cloned


def _route_location_results(
    text: str,
    results: List,
    *,
    location_entity: str,
) -> List:
    routed = []
    for result in results:
        if result.entity_type != location_entity:
            routed.append(result)
            continue

        trimmed = _trim_location_result_to_address(text, result)
        if trimmed is not None:
            routed.append(trimmed)

    return routed


def _ranges_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _prefer_longer_or_higher_score(current, candidate):
    current_len = current.end - current.start
    candidate_len = candidate.end - candidate.start
    if candidate_len != current_len:
        return candidate if candidate_len > current_len else current
    if candidate.score != current.score:
        return candidate if candidate.score > current.score else current
    return current


def _merge_numeric_entity_results(text: str, results: List, *, entity: str, min_digits: int) -> List:
    merged: List = []
    for result in results:
        if result.entity_type != entity:
            merged.append(result)
            continue

        digits = _normalize_digits(_slice_text(text, result.start, result.end))
        if len(digits) < min_digits:
            merged.append(result)
            continue

        replacement_index = None
        for index, existing in enumerate(merged):
            if existing.entity_type != entity:
                continue
            existing_digits = _normalize_digits(_slice_text(text, existing.start, existing.end))
            if digits != existing_digits:
                continue
            if not _ranges_overlap(result.start, result.end, existing.start, existing.end):
                continue
            replacement_index = index
            break

        if replacement_index is None:
            merged.append(result)
            continue

        merged[replacement_index] = _prefer_longer_or_higher_score(
            merged[replacement_index],
            result,
        )

    return merged


def _resolve_same_category_overlaps(
    results: List,
    *,
    score_close_threshold: float = SAME_CATEGORY_SCORE_CLOSE_THRESHOLD,
) -> List:
    """Collapse overlapping same-entity_type results to a single span.

    For two results with the same entity_type whose spans overlap:
      - If the score gap is >= score_close_threshold, keep the higher-score
        result.
      - Otherwise, keep the longer span; on length tie, keep the higher
        score.
    The surviving result's score is bumped to the max of the pair so a
    high-confidence regex hit doesn't lose its score when a slightly longer
    model span wins the span tiebreak.
    """
    kept: List = []
    for result in results:
        replace_index = None
        for index, existing in enumerate(kept):
            if existing.entity_type != result.entity_type:
                continue
            if not _ranges_overlap(
                result.start, result.end, existing.start, existing.end
            ):
                continue
            replace_index = index
            break

        if replace_index is None:
            kept.append(result)
            continue

        existing = kept[replace_index]
        max_score = max(existing.score, result.score)
        if abs(existing.score - result.score) >= score_close_threshold:
            winner = existing if existing.score >= result.score else result
        else:
            winner = _prefer_longer_or_higher_score(existing, result)
        winner.score = max_score
        kept[replace_index] = winner

    return kept


def _suppress_phone_overlapping_other_entities(text: str, results: List) -> List:
    """Drop PHONE_NUMBER results that double-tag an SSN/CC span or sit inside an email.

    Real phones, SSNs, and credit cards can all share the dashed-digit shape, so
    PhoneRecognizer happily fires on an SSN span even when ContextAwareUsSsnRecognizer
    has already labeled it. Likewise, the digit suffix of an email local part
    (`morales85@…`) is sometimes matched as a phone. This helper removes those
    cases by checking each PHONE_NUMBER against the other recognizers' results.
    """
    other_spans: List[Tuple[str, int, int, str]] = []
    for result in results:
        if result.entity_type in PHONE_DIGIT_OVERLAP_ENTITIES:
            digits = _normalize_digits(_slice_text(text, result.start, result.end))
            other_spans.append((result.entity_type, result.start, result.end, digits))
        elif result.entity_type == EMAIL_ENTITY:
            other_spans.append((EMAIL_ENTITY, result.start, result.end, ""))

    if not other_spans:
        return results

    suppressed: List = []
    for result in results:
        if result.entity_type != PHONE_ENTITY:
            suppressed.append(result)
            continue

        phone_digits = _normalize_digits(_slice_text(text, result.start, result.end))
        drop = False
        for entity_type, start, end, digits in other_spans:
            if entity_type == EMAIL_ENTITY:
                if start <= result.start and result.end <= end:
                    drop = True
                    break
                continue
            if not _ranges_overlap(result.start, result.end, start, end):
                continue
            if not phone_digits:
                continue
            if phone_digits == digits or phone_digits in digits:
                drop = True
                break
        if not drop:
            suppressed.append(result)
    return suppressed


def is_gliner_result(result, free_text_name: str, dob_name: str) -> bool:
    """Return whether a result came from one of the GLiNER recognizers."""
    return _get_recognizer_name(result) in {free_text_name, dob_name}


def filter_results_by_source(
    *,
    text: str,
    results: List,
    use_source_routing: bool,
    gliner_owned_entities,
    regex_owned_entities,
    gliner_recognizer_names,
    route_location_results: bool = False,
    location_entity: str = LOCATION_ENTITY,
) -> List:
    """Apply routing and collapse overlapping equivalent phone/card spans."""

    filtered = []
    free_text_name, dob_name = gliner_recognizer_names
    for result in results:
        result_is_gliner = is_gliner_result(result, free_text_name, dob_name)
        entity = result.entity_type
        if entity in gliner_owned_entities and not result_is_gliner:
            continue
        if entity in regex_owned_entities and result_is_gliner:
            continue
        filtered.append(result)

    if route_location_results:
        filtered = _route_location_results(
            text,
            filtered,
            location_entity=location_entity,
        )

    filtered = _merge_numeric_entity_results(
        text,
        filtered,
        entity=PHONE_ENTITY,
        min_digits=10,
    )
    filtered = _merge_numeric_entity_results(
        text,
        filtered,
        entity=CREDIT_CARD_ENTITY,
        min_digits=13,
    )

    filtered = _resolve_same_category_overlaps(filtered)

    filtered = _suppress_phone_overlapping_other_entities(text, filtered)

    best_by_key: Dict[Tuple[str, int, int, str], object] = {}
    for result in filtered:
        key = result_dedupe_key(text, result)
        best = best_by_key.get(key)
        if best is None or result.score > best.score:
            best_by_key[key] = result
    return list(best_by_key.values())
