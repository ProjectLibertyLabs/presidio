import re
from typing import List, Optional, Sequence

import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException

from presidio_analyzer import (
    AnalysisExplanation,
    EntityRecognizer,
    LocalRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpArtifacts


class PhoneRecognizer(LocalRecognizer):
    """Recognize multi-regional phone numbers.

     Using python-phonenumbers, along with fixed and regional context words.
    :param context: Base context words for enhancing the assurance scores.
    :param supported_language: Language this recognizer supports
    :param supported_regions: The regions for phone number matching and validation
    :param leniency: The strictness level of phone number formats.
    Accepts values from 0 to 3, where 0 is the lenient and 3 is the most strictest.
    """

    SCORE = 0.4
    CONTEXT = ["phone", "number", "telephone", "cell", "cellphone", "mobile", "call"]
    POSITIVE_CONTEXT_TERMS = (
        "phone",
        "telephone",
        "mobile",
        "cell",
        "call",
        "contact",
        "fax",
    )
    NEGATIVE_CONTEXT_TERMS = (
        "account",
        "routing",
        "biometric",
        "policy",
        "record",
        "identifier",
        "customer id",
        "policy number",
        "account number",
        "pin",
        "otp",
    )
    DEFAULT_SUPPORTED_REGIONS = ("US", "UK", "DE", "FE", "IL", "IN", "CA", "BR")
    IPV4_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    DOT_BETWEEN_DIGITS_REGEX = re.compile(r"\d\.\d")
    YEAR_REGEX = re.compile(r"^(?:19|20)\d{2}$")
    EMAIL_REGEX = re.compile(r"\S+@\S+")
    EMAIL_SCAN_WINDOW_CHARS = 60
    CONTEXT_FALLBACK_LENIENCY = 0

    def __init__(
        self,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        # For all regions, use phonenumbers.SUPPORTED_REGIONS
        supported_regions=DEFAULT_SUPPORTED_REGIONS,
        leniency: Optional[int] = 1,
        require_possible_number: bool = False,
        require_valid_number: bool = False,
        positive_context_terms: Optional[Sequence[str]] = None,
        negative_context_terms: Optional[Sequence[str]] = None,
        context_window_chars: int = 40,
        reject_numeric_id_without_context: bool = True,
        reject_preceding_letter: bool = True,
        reject_dot_separator: bool = True,
        reject_year_token: bool = True,
        reject_inside_email: bool = True,
        min_digits_without_context: int = 7,
        name: Optional[str] = None,
    ):
        context = context if context else self.CONTEXT
        self.supported_regions = supported_regions
        self.leniency = leniency
        self.require_possible_number = require_possible_number
        self.require_valid_number = require_valid_number
        self.context_window_chars = context_window_chars
        self.reject_numeric_id_without_context = reject_numeric_id_without_context
        self.reject_preceding_letter = reject_preceding_letter
        self.reject_dot_separator = reject_dot_separator
        self.reject_year_token = reject_year_token
        self.reject_inside_email = reject_inside_email
        self.min_digits_without_context = min_digits_without_context
        self.positive_context_terms = tuple(
            term.lower()
            for term in (
                positive_context_terms
                if positive_context_terms is not None
                else self.POSITIVE_CONTEXT_TERMS
            )
        )
        self.negative_context_terms = tuple(
            term.lower()
            for term in (
                negative_context_terms
                if negative_context_terms is not None
                else self.NEGATIVE_CONTEXT_TERMS
            )
        )
        super().__init__(
            supported_entities=self.get_supported_entities(),
            supported_language=supported_language,
            context=context,
            name=name,
        )

    def load(self) -> None:  # noqa: D102
        pass

    def get_supported_entities(self):  # noqa: D102
        return ["PHONE_NUMBER"]

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts: NlpArtifacts = None
    ) -> List[RecognizerResult]:
        """Analyzes text to detect phone numbers using python-phonenumbers.

        Iterates over entities, fetching regions, then matching regional
        phone numbers patterns against the text.
        :param text: Text to be analyzed
        :param entities: Entities this recognizer can detect
        :param nlp_artifacts: Additional metadata from the NLP engine
        :return: List of phone numbers RecognizerResults
        """
        results = []
        seen_spans = set()
        for region in self.supported_regions:
            for match in self._iter_phone_matches(
                text=text,
                region=region,
                leniency=self.leniency,
            ):
                result = self._build_result_from_match(
                    match=match,
                    text=text,
                    region=region,
                    require_explicit_context=False,
                )
                if result is None:
                    continue
                seen_spans.add((result.start, result.end))
                results.append(result)

        if self.leniency != self.CONTEXT_FALLBACK_LENIENCY:
            for region in self.supported_regions:
                for match in self._iter_phone_matches(
                    text=text,
                    region=region,
                    leniency=self.CONTEXT_FALLBACK_LENIENCY,
                ):
                    if (match.start, match.end) in seen_spans:
                        continue
                    result = self._build_result_from_match(
                        match=match,
                        text=text,
                        region=region,
                        require_explicit_context=True,
                    )
                    if result is None:
                        continue
                    seen_spans.add((result.start, result.end))
                    results.append(result)

        return EntityRecognizer.remove_duplicates(results)

    @staticmethod
    def _iter_phone_matches(text: str, region: str, leniency: int):
        yield from phonenumbers.PhoneNumberMatcher(text, region, leniency=leniency)

    def _build_result_from_match(
        self,
        match,
        text: str,
        region: str,
        require_explicit_context: bool,
    ) -> Optional[RecognizerResult]:
        try:
            match_text = text[match.start : match.end]
            has_positive_context, _ = self._context_flags(
                text=text,
                start=match.start,
                end=match.end,
            )
            if require_explicit_context and not has_positive_context:
                return None

            if self._is_invalid_phone_candidate(
                text=text,
                match_text=match_text,
                start=match.start,
                end=match.end,
            ):
                return None

            parsed_number = match.number
            if (
                self.require_possible_number
                and not phonenumbers.is_possible_number(parsed_number)
            ):
                return None
            if self.require_valid_number and not phonenumbers.is_valid_number(
                parsed_number
            ):
                return None

            detected_region = phonenumbers.region_code_for_number(parsed_number)
            return self._get_recognizer_result(
                match, text, detected_region or region, None
            )
        except NumberParseException:
            return None

    def _context_flags(self, text: str, start: int, end: int) -> tuple[bool, bool]:
        window_start = max(0, start - self.context_window_chars)
        window_end = min(len(text), end + self.context_window_chars)
        context_window = text[window_start:window_end].lower()

        has_positive_context = any(
            term in context_window for term in self.positive_context_terms
        )
        has_negative_context = any(
            term in context_window for term in self.negative_context_terms
        )
        return has_positive_context, has_negative_context

    def _is_invalid_phone_candidate(
        self, text: str, match_text: str, start: int, end: int
    ) -> bool:
        if self.IPV4_REGEX.match(match_text):
            return True

        has_positive_context, has_negative_context = self._context_flags(
            text=text,
            start=start,
            end=end,
        )

        if has_negative_context and not has_positive_context:
            return True

        digit_count = sum(1 for c in match_text if c.isdigit())
        if (
            self.min_digits_without_context > 0
            and digit_count < self.min_digits_without_context
            and not has_positive_context
        ):
            return True

        if (
            self.reject_preceding_letter
            and start > 0
            and text[start - 1].isalpha()
        ):
            return True

        if (
            self.reject_dot_separator
            and self.DOT_BETWEEN_DIGITS_REGEX.search(match_text)
        ):
            return True

        if (
            self.reject_year_token
            and not has_positive_context
            and self.YEAR_REGEX.match(match_text.strip())
        ):
            return True

        if self.reject_inside_email and self._is_inside_email(text, start, end):
            return True

        if (
            self.reject_numeric_id_without_context
            and "+" not in match_text
            and not has_positive_context
            and any(sep in match_text for sep in ("-", " ", "(", ")"))
        ):
            digit_groups = [
                grp for grp in re.split(r"[()\s\-]+", match_text) if grp.isdigit()
            ]
            if digit_groups and any(len(group) > 7 for group in digit_groups):
                return True

        return False

    def _is_inside_email(self, text: str, start: int, end: int) -> bool:
        window_start = max(0, start - self.EMAIL_SCAN_WINDOW_CHARS)
        window_end = min(len(text), end + self.EMAIL_SCAN_WINDOW_CHARS)
        for match in self.EMAIL_REGEX.finditer(text, window_start, window_end):
            if match.start() <= start and end <= match.end():
                return True
        return False

    def _get_recognizer_result(self, match, text, region, nlp_artifacts):
        result = RecognizerResult(
            entity_type="PHONE_NUMBER",
            start=match.start,
            end=match.end,
            score=self.SCORE,
            analysis_explanation=self._get_analysis_explanation(region),
            recognition_metadata={
                RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
            },
        )

        return result

    def _get_analysis_explanation(self, region):
        return AnalysisExplanation(
            recognizer=PhoneRecognizer.__name__,
            original_score=self.SCORE,
            textual_explanation=f"Recognized as {region} region phone number, "
            f"using PhoneRecognizer",
        )
