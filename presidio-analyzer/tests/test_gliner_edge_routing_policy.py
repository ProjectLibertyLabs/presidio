from presidio_analyzer.analysis_explanation import AnalysisExplanation
from presidio_analyzer.analyzer.gliner_edge.routing_policy import (
    _resolve_same_category_overlaps,
    filter_results_by_source,
)
from presidio_analyzer.recognizer_result import RecognizerResult


def _result(entity, start, end, score, recognizer_name):
    return RecognizerResult(
        entity_type=entity,
        start=start,
        end=end,
        score=score,
        analysis_explanation=AnalysisExplanation(
            recognizer=recognizer_name,
            original_score=score,
            textual_explanation="test",
        ),
    )


def _span(text, value):
    start = text.index(value)
    return start, start + len(value)


def test_filter_results_by_source_keeps_owned_entities():
    text = "John Doe email john@example.com"
    results = [
        _result("PERSON", 0, 8, 0.8, "GLiNERFreeTextRecognizer"),
        _result("PERSON", 0, 8, 0.9, "SpacyRecognizer"),
        _result("EMAIL_ADDRESS", 15, 31, 0.7, "EmailRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=True,
        gliner_owned_entities={"PERSON"},
        regex_owned_entities={"EMAIL_ADDRESS"},
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
    )

    assert len(filtered) == 2
    assert any(r.entity_type == "PERSON" and r.analysis_explanation.recognizer == "GLiNERFreeTextRecognizer" for r in filtered)
    assert any(r.entity_type == "EMAIL_ADDRESS" for r in filtered)


def test_filter_results_by_source_trims_broad_address_to_street_core():
    text = (
        "The property located at 908 Ember Pine Rd, Alder Creek, Summit County, "
        "CO, 80435 is being transferred."
    )
    results = [
        _result("LOCATION", *_span(text, "908"), 0.99, "PrivacyFilterRecognizer"),
        _result("LOCATION", *_span(text, "Ember Pine Rd"), 0.99, "PrivacyFilterRecognizer"),
        _result("LOCATION", *_span(text, "Alder Creek"), 0.99, "PrivacyFilterRecognizer"),
        _result("LOCATION", *_span(text, "Summit County"), 0.99, "PrivacyFilterRecognizer"),
        _result("LOCATION", *_span(text, "80435"), 1.0, "PrivacyFilterRecognizer"),
        _result(
            "LOCATION",
            *_span(text, "908 Ember Pine Rd, Alder Creek, Summit County, CO, 80435"),
            0.83,
            "GLiNERFreeTextRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "908 Ember Pine Rd"


def test_filter_results_by_source_drops_coordinates_but_keeps_real_address():
    text = (
        "Incident at 40.7441 N, 73.9844 W. Pedro lives at "
        "94 Cedar Lantern Drive Southeast."
    )
    results = [
        _result(
            "LOCATION",
            *_span(text, "40.7441 N, 73.9844 W."),
            0.93,
            "PrivacyFilterRecognizer",
        ),
        _result(
            "LOCATION",
            *_span(text, "94 Cedar Lantern Drive Southeast"),
            1.0,
            "PrivacyFilterRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "94 Cedar Lantern Drive Southeast"


def test_filter_results_by_source_keeps_unit_detail_when_trimming_address():
    text = "Ship to 123 Main St Apt 5, Springfield for delivery."
    results = [
        _result(
            "LOCATION",
            *_span(text, "123 Main St Apt 5, Springfield"),
            0.87,
            "GLiNERFreeTextRecognizer",
        )
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "123 Main St Apt 5"


def test_filter_results_by_source_preserves_multiple_occurrences_after_trimming():
    text = (
        "Street Address: 71 Juniper Heights Blvd. "
        "Mail copies to 71 Juniper Heights Blvd, Fairview, Colorado."
    )
    results = [
        _result(
            "LOCATION",
            *_span(text, "71 Juniper Heights Blvd"),
            0.98,
            "PrivacyFilterRecognizer",
        ),
        _result(
            "LOCATION",
            *_span(text, "71 Juniper Heights Blvd, Fairview, Colorado"),
            0.84,
            "GLiNERFreeTextRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    values = [text[result.start : result.end] for result in filtered]
    assert values == ["71 Juniper Heights Blvd", "71 Juniper Heights Blvd"]


def test_filter_results_by_source_requires_leading_house_number():
    text = "The borrower resides at 418 State Route 934."
    results = [
        _result(
            "LOCATION",
            *_span(text, "State Route 934"),
            0.81,
            "PrivacyFilterRecognizer",
        ),
        _result(
            "LOCATION",
            *_span(text, "418 State Route 934"),
            0.88,
            "GLiNERFreeTextRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "418 State Route 934"


def test_filter_results_by_source_drops_mac_like_location_noise():
    text = "Device inventory recorded 00:1A:2B:3C:4D:5E beside 64 Orchard View Way."
    results = [
        _result(
            "LOCATION",
            *_span(text, "00:1A:2B:3C:4D:5E"),
            0.82,
            "PrivacyFilterRecognizer",
        ),
        _result(
            "LOCATION",
            *_span(text, "64 Orchard View Way"),
            0.91,
            "PrivacyFilterRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=True,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "64 Orchard View Way"


def test_filter_results_by_source_merges_equivalent_phone_spans():
    text = "For urgent questions, call (212) 555-0148 today."
    results = [
        _result("PHONE_NUMBER", *_span(text, "212) 555-0148"), 0.67, "PrivacyFilterRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "(212) 555-0148"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "(212) 555-0148"


def test_filter_results_by_source_merges_overlapping_full_card_hits():
    text = "Payment card [4111 1111 1111 1111] is stored for recurring billing."
    results = [
        _result(
            "CREDIT_CARD",
            *_span(text, "4111 1111 1111 1111"),
            0.86,
            "PrivacyFilterRecognizer",
        ),
        _result(
            "CREDIT_CARD",
            *_span(text, "[4111 1111 1111 1111]"),
            1.0,
            "CreditCardRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert text[filtered[0].start : filtered[0].end] == "[4111 1111 1111 1111]"


def test_phone_suppressed_when_ssn_overlaps_same_digits():
    text = "Borrower SSN 201-13-6708 on the loan application."
    results = [
        _result("US_SSN", *_span(text, "201-13-6708"), 0.85, "ContextAwareUsSsnRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "201-13-6708"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert filtered[0].entity_type == "US_SSN"


def test_phone_suppressed_when_credit_card_substring():
    text = "Card number 3963 333322 08054 charged for the order."
    results = [
        _result("CREDIT_CARD", *_span(text, "3963 333322 08054"), 1.0, "CreditCardRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "333322"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert filtered[0].entity_type == "CREDIT_CARD"


def test_phone_suppressed_when_inside_email_span():
    text = "Contact us at morales85@icloud.com for details."
    results = [
        _result("EMAIL_ADDRESS", *_span(text, "morales85@icloud.com"), 1.0, "EmailRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "85"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert filtered[0].entity_type == "EMAIL_ADDRESS"


def test_phone_kept_when_no_overlap_with_other_entities():
    text = "Call 415-555-0132 and email moreau@example.com."
    results = [
        _result("EMAIL_ADDRESS", *_span(text, "moreau@example.com"), 1.0, "EmailRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "415-555-0132"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 2
    assert {r.entity_type for r in filtered} == {"PHONE_NUMBER", "EMAIL_ADDRESS"}


def test_low_confidence_phone_suppressed_when_contained_in_location():
    """Drop unboosted phone fragments contained in stronger addresses."""
    text = "Street Address: 175 James Blvd\nPhone Number: 615-898-4350"
    results = [
        _result("LOCATION", *_span(text, "175 James Blvd"), 0.999, "SpacyRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "175"), 0.4, "PhoneRecognizer"),
        _result(
            "PHONE_NUMBER",
            *_span(text, "615-898-4350"),
            0.999,
            "PhoneRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    values = {text[r.start : r.end] for r in filtered}
    assert values == {"175 James Blvd", "615-898-4350"}


def test_low_confidence_phone_suppressed_when_contained_in_dob():
    """Drop unboosted phone fragments contained in stronger DOB spans."""
    text = "Date of Birth: 1990-10-09\nPhone Number: 941-373-0385"
    results = [
        _result("DOB", *_span(text, "1990-10-09"), 1.0, "DateRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "1990-10-09"), 0.4, "PhoneRecognizer"),
        _result(
            "PHONE_NUMBER",
            *_span(text, "941-373-0385"),
            0.999,
            "PhoneRecognizer",
        ),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    values = {text[r.start : r.end] for r in filtered}
    assert values == {"1990-10-09", "941-373-0385"}


def test_low_confidence_phone_kept_without_containing_higher_score_entity():
    """Keep unboosted phones when no stronger containing entity exists."""
    text = "Phone Number: 615-898-4350"
    results = [
        _result("PHONE_NUMBER", *_span(text, "615-898-4350"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert filtered[0].entity_type == "PHONE_NUMBER"


def test_low_confidence_phone_kept_when_only_partially_overlapping_other_entity():
    """Keep unboosted phones when a stronger entity only partially overlaps."""
    text = "Value 12345 Main"
    results = [
        _result("LOCATION", *_span(text, "345 Main"), 0.999, "SpacyRecognizer"),
        _result("PHONE_NUMBER", *_span(text, "12345"), 0.4, "PhoneRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 2
    assert {r.entity_type for r in filtered} == {"LOCATION", "PHONE_NUMBER"}


def test_resolves_same_category_overlapping_emails_keeps_longer_when_scores_close():
    text = "Contact me at richardh30@icloud.com today."
    short_start, short_end = _span(text, "richardh30@icloud.com")
    long_start, long_end = short_start, short_end + 1
    results = [
        _result("EMAIL_ADDRESS", short_start, short_end, 1.0, "EmailRecognizer"),
        _result("EMAIL_ADDRESS", long_start, long_end, 0.998, "PrivacyFilterRecognizer"),
    ]

    filtered = filter_results_by_source(
        text=text,
        results=results,
        use_source_routing=False,
        gliner_owned_entities=set(),
        regex_owned_entities=set(),
        gliner_recognizer_names=("GLiNERFreeTextRecognizer", "GLiNERDobRecognizer"),
        route_location_results=False,
    )

    assert len(filtered) == 1
    assert filtered[0].entity_type == "EMAIL_ADDRESS"
    assert filtered[0].start == long_start
    assert filtered[0].end == long_end
    assert filtered[0].score == 1.0


def test_resolves_same_category_overlap_keeps_higher_score_when_scores_far_apart():
    results = [
        _result("EMAIL_ADDRESS", 100, 120, 0.95, "EmailRecognizer"),
        _result("EMAIL_ADDRESS", 100, 130, 0.40, "PrivacyFilterRecognizer"),
    ]

    resolved = _resolve_same_category_overlaps(results)

    assert len(resolved) == 1
    assert resolved[0].start == 100
    assert resolved[0].end == 120
    assert resolved[0].score == 0.95


def test_resolves_same_category_overlap_no_op_when_spans_disjoint():
    results = [
        _result("EMAIL_ADDRESS", 10, 25, 0.9, "EmailRecognizer"),
        _result("EMAIL_ADDRESS", 60, 80, 0.95, "PrivacyFilterRecognizer"),
    ]

    resolved = _resolve_same_category_overlaps(results)

    assert len(resolved) == 2
    assert {(r.start, r.end) for r in resolved} == {(10, 25), (60, 80)}


def test_resolves_same_category_overlap_leaves_cross_category_alone():
    results = [
        _result("EMAIL_ADDRESS", 100, 120, 0.99, "EmailRecognizer"),
        _result("PHONE_NUMBER", 100, 120, 0.85, "PrivacyFilterRecognizer"),
    ]

    resolved = _resolve_same_category_overlaps(results)

    assert len(resolved) == 2
    assert {r.entity_type for r in resolved} == {"EMAIL_ADDRESS", "PHONE_NUMBER"}
