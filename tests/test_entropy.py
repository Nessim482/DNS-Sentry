from dns_sentry.entropy import shannon_entropy


def test_empty_string_entropy_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_repetitive_string_entropy_is_low() -> None:
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_base64_like_string_entropy_is_high() -> None:
    entropy = shannon_entropy("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh")

    assert entropy > 3.5

