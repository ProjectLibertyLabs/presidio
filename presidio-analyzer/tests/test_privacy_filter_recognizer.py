from presidio_analyzer.analyzer.privacy_filter.recognizers import (
    _Detection,
    _filter_phone_context,
    _validate_and_trim_phone,
)


def test_privacy_filter_phone_context_drops_non_phone_numeric_ids():
    text = (
        "Patient Information: First Name: Juan. "
        "Medical Record Number: 230512-2846. Date of Birth: N/A."
    )
    detection = _Detection(
        label="private_phone",
        score=0.99,
        start=text.index("230512-2846"),
        end=text.index("230512-2846") + len("230512-2846"),
    )

    trimmed = _validate_and_trim_phone(text, detection)
    assert trimmed is not None
    assert _filter_phone_context(text, trimmed) is None


def test_privacy_filter_phone_context_keeps_fax_as_phone_pii():
    text = "The log entry also noted a fax number of 872-802-3377."
    detection = _Detection(
        label="private_phone",
        score=0.99,
        start=text.index("872-802-3377"),
        end=text.index("872-802-3377") + len("872-802-3377"),
    )

    trimmed = _validate_and_trim_phone(text, detection)
    assert trimmed is not None
    kept = _filter_phone_context(text, trimmed)
    assert kept is not None
    assert text[kept.start : kept.end] == "872-802-3377"
