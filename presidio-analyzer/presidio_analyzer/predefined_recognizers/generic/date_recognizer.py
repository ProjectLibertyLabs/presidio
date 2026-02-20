from typing import List, Optional, Sequence

from presidio_analyzer import Pattern, PatternRecognizer


class DateRecognizer(PatternRecognizer):
    """
    Recognize date using regex.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    """

    PATTERNS = [
        Pattern(
            "ISO 8601 datetime",
            r"\b(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))\b",
            0.8,
        ),
        Pattern(
            "mm/dd/yyyy or mm/dd/yy",
            r"\b(([1-9]|0[1-9]|1[0-2])/([1-9]|0[1-9]|[1-2][0-9]|3[0-1])/(\d{4}|\d{2}))\b",
            0.6,
        ),
        Pattern(
            "dd/mm/yyyy or dd/mm/yy",
            r"\b(([1-9]|0[1-9]|[1-2][0-9]|3[0-1])/([1-9]|0[1-9]|1[0-2])/(\d{4}|\d{2}))\b",
            0.6,
        ),
        Pattern(
            "yyyy/mm/dd",
            r"\b(\d{4}/([1-9]|0[1-9]|1[0-2])/([1-9]|0[1-9]|[1-2][0-9]|3[0-1]))\b",
            0.6,
        ),
        Pattern(
            "mm-dd-yyyy",
            r"\b(([1-9]|0[1-9]|1[0-2])-([1-9]|0[1-9]|[1-2][0-9]|3[0-1])-\d{4})\b",
            0.6,
        ),
        Pattern(
            "dd-mm-yyyy",
            r"\b(([1-9]|0[1-9]|[1-2][0-9]|3[0-1])-([1-9]|0[1-9]|1[0-2])-\d{4})\b",
            0.6,
        ),
        Pattern(
            "yyyy-mm-dd",
            r"\b(\d{4}-([1-9]|0[1-9]|1[0-2])-([1-9]|0[1-9]|[1-2][0-9]|3[0-1]))\b",
            0.6,
        ),
        Pattern(
            "dd.mm.yyyy or dd.mm.yy",
            r"\b(([1-9]|0[1-9]|[1-2][0-9]|3[0-1])\.([1-9]|0[1-9]|1[0-2])\.(\d{4}|\d{2}))\b",
            0.6,
        ),
        Pattern(
            "dd-MMM-yyyy or dd-MMM-yy",
            r"\b(([1-9]|0[1-9]|[1-2][0-9]|3[0-1])-(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(\d{4}|\d{2}))\b",
            0.6,
        ),
        Pattern(
            "MMM-yyyy or MMM-yy",
            r"\b((JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(\d{4}|\d{2}))\b",
            0.6,
        ),
        Pattern(
            "dd-MMM or dd-MMM",
            r"\b(([1-9]|0[1-9]|[1-2][0-9]|3[0-1])-(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC))\b",
            0.6,
        ),
        Pattern(
            "mm/yyyy or m/yyyy",
            r"\b(([1-9]|0[1-9]|1[0-2])/\d{4})\b",
            0.2,
        ),
        Pattern(
            "mm/yy or m/yy",
            r"\b(([1-9]|0[1-9]|1[0-2])/\d{2})\b",
            0.1,
        ),
    ]

    CONTEXT = ["date", "birthday"]
    BIRTH_CONTEXT_TERMS = ("dob", "date of birth", "born", "birth", "birthday")
    NON_BIRTH_CONTEXT_TERMS = (
        "date of death",
        "death",
        "report",
        "deadline",
        "departure",
        "arrival",
        "issued",
        "event",
        "workshop",
        "timestamp",
        "finalized",
    )

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "DATE_TIME",
        require_birth_context: bool = True,
        birth_context_terms: Optional[Sequence[str]] = None,
        non_birth_context_terms: Optional[Sequence[str]] = None,
        context_window_chars: int = 45,
        name: Optional[str] = None,
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        self.require_birth_context = require_birth_context
        self.context_window_chars = context_window_chars
        self.birth_context_terms = tuple(
            term.lower()
            for term in (
                birth_context_terms
                if birth_context_terms is not None
                else self.BIRTH_CONTEXT_TERMS
            )
        )
        self.non_birth_context_terms = tuple(
            term.lower()
            for term in (
                non_birth_context_terms
                if non_birth_context_terms is not None
                else self.NON_BIRTH_CONTEXT_TERMS
            )
        )
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name=name,
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None,
        regex_flags: Optional[int] = None,
    ):
        results = super().analyze(
            text=text,
            entities=entities,
            nlp_artifacts=nlp_artifacts,
            regex_flags=regex_flags,
        )
        if not self.require_birth_context:
            return results

        filtered_results = []
        for result in results:
            start = result.start
            end = result.end
            window_start = max(0, start - self.context_window_chars)
            window_end = min(len(text), end + self.context_window_chars)
            context_window = text[window_start:window_end].lower()
            has_birth_context = any(
                term in context_window for term in self.birth_context_terms
            )
            has_non_birth_context = any(
                term in context_window for term in self.non_birth_context_terms
            )

            if not has_birth_context:
                continue
            if has_non_birth_context:
                continue

            filtered_results.append(result)

        return filtered_results
