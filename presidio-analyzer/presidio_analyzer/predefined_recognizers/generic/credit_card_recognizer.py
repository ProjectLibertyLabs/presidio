from typing import List, Optional, Sequence, Tuple

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer


class CreditCardRecognizer(PatternRecognizer):
    """
    Recognize common credit card numbers using regex + checksum.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    :param replacement_pairs: List of tuples with potential replacement values
    for different strings to be used during pattern matching.
    This can allow a greater variety in input, for example by removing dashes or spaces.
    """

    PATTERNS = [
        Pattern(
            "All Credit Cards (weak)",
            r"\b(?!1\d{12}(?!\d))((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b",  # noqa: E501
            0.3,
        ),
    ]

    CONTEXT = [
        "credit",
        "card",
        "visa",
        "mastercard",
        "cc ",
        "amex",
        "discover",
        "jcb",
        "diners",
        "maestro",
        "instapayment",
    ]
    POSITIVE_CONTEXT_TERMS = (
        "credit",
        "debit",
        "card",
        "visa",
        "mastercard",
        "amex",
        "discover",
        "transaction",
        "payment",
        "billing",
    )
    NEGATIVE_CONTEXT_TERMS = (
        "routing",
        "account",
        "pin",
        "otp",
        "invoice",
        "order",
        "ticket",
        "reservation",
    )

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "CREDIT_CARD",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
        min_card_digits: int = 13,
        max_card_digits: int = 19,
        reject_partials: bool = True,
        context_window_chars: int = 40,
        positive_context_terms: Optional[Sequence[str]] = None,
        negative_context_terms: Optional[Sequence[str]] = None,
        apply_context_filter: bool = True,
        name: Optional[str] = None,
    ):
        self.replacement_pairs = (
            replacement_pairs if replacement_pairs else [("-", ""), (" ", "")]
        )
        self.min_card_digits = min_card_digits
        self.max_card_digits = max_card_digits
        self.reject_partials = reject_partials
        self.context_window_chars = context_window_chars
        self.apply_context_filter = apply_context_filter
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
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name=name,
        )

    def validate_result(self, pattern_text: str) -> bool:  # noqa: D102
        sanitized_value = EntityRecognizer.sanitize_value(
            pattern_text, self.replacement_pairs
        )
        if self.reject_partials and (
            len(sanitized_value) < self.min_card_digits
            or len(sanitized_value) > self.max_card_digits
        ):
            return False
        checksum = self.__luhn_checksum(sanitized_value)

        return checksum

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None, regex_flags=None
    ):
        results = super().analyze(
            text=text,
            entities=entities,
            nlp_artifacts=nlp_artifacts,
            regex_flags=regex_flags,
        )
        if not self.apply_context_filter:
            return results

        filtered_results = []
        for result in results:
            window_start = max(0, result.start - self.context_window_chars)
            window_end = min(len(text), result.end + self.context_window_chars)
            context_window = text[window_start:window_end].lower()
            has_positive_context = any(
                term in context_window for term in self.positive_context_terms
            )
            has_negative_context = any(
                term in context_window for term in self.negative_context_terms
            )
            if has_negative_context and not has_positive_context:
                continue
            filtered_results.append(result)

        return filtered_results

    @staticmethod
    def __luhn_checksum(sanitized_value: str) -> bool:
        def digits_of(n: str) -> List[int]:
            return [int(dig) for dig in str(n)]

        digits = digits_of(sanitized_value)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(str(d * 2)))
        return checksum % 10 == 0
