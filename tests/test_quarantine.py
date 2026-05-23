from dns_sentry.quarantine import QuarantineState, apply_action


def scored_result(action: str, domain: str = "Example.COM.") -> dict:
    return {
        "domain": domain,
        "risk_score": 75,
        "severity": "Dangerous",
        "action": action,
        "reasons": ["Test scoring reason"],
    }


def test_allow_returns_allowed_without_quarantine() -> None:
    decision = apply_action(scored_result("allow"))

    assert decision["domain"] == "example.com"
    assert decision["action"] == "allow"
    assert decision["applied"] is True
    assert decision["quarantined"] is False
    assert decision["containment_required"] is False
    assert "allowed" in decision["message"].lower()


def test_log_returns_logged_without_quarantine() -> None:
    decision = apply_action(scored_result("log"))

    assert decision["applied"] is True
    assert decision["quarantined"] is False
    assert decision["containment_required"] is False
    assert "logged" in decision["message"].lower()


def test_alert_returns_alert_required() -> None:
    decision = apply_action(scored_result("alert"))

    assert decision["applied"] is True
    assert decision["quarantined"] is False
    assert decision["containment_required"] is False
    assert "alert required" in decision["message"].lower()


def test_strong_alert_returns_strong_alert_required() -> None:
    decision = apply_action(scored_result("strong_alert"))

    assert decision["applied"] is True
    assert decision["quarantined"] is False
    assert decision["containment_required"] is False
    assert "strong" in decision["message"].lower()
    assert "alert required" in decision["message"].lower()


def test_quarantine_returns_quarantined_true() -> None:
    decision = apply_action(scored_result("quarantine"))

    assert decision["applied"] is True
    assert decision["quarantined"] is True
    assert decision["containment_required"] is False
    assert "logical quarantine applied" in decision["message"].lower()


def test_quarantine_and_containment_requires_containment() -> None:
    decision = apply_action(scored_result("quarantine_and_containment"))

    assert decision["applied"] is True
    assert decision["quarantined"] is True
    assert decision["containment_required"] is True
    assert "logical quarantine and containment required" in decision["message"].lower()


def test_unknown_action_returns_not_applied() -> None:
    decision = apply_action(scored_result("unexpected_action"))

    assert decision["action"] == "unexpected_action"
    assert decision["applied"] is False
    assert decision["quarantined"] is False
    assert decision["containment_required"] is False
    assert "unknown action" in decision["message"].lower()


def test_apply_action_copies_reasons() -> None:
    result = scored_result("alert")
    decision = apply_action(result)
    result["reasons"].append("Mutated after decision")

    assert decision["reasons"] == ["Test scoring reason"]


def test_quarantine_state_adds_domain() -> None:
    state = QuarantineState()

    state.add(scored_result("quarantine", domain="Danger.Example.TEST."))

    entries = state.list_quarantined()
    assert len(entries) == 1
    assert entries[0]["domain"] == "danger.example.test"
    assert entries[0]["risk_score"] == 75
    assert entries[0]["severity"] == "Dangerous"
    assert entries[0]["action"] == "quarantine"
    assert entries[0]["reasons"] == ["Test scoring reason"]
    assert isinstance(entries[0]["timestamp"], float)


def test_quarantine_state_detects_quarantined_domain() -> None:
    state = QuarantineState()

    state.add(scored_result("quarantine", domain="Danger.Example.TEST."))

    assert state.is_quarantined("danger.example.test") is True
    assert state.is_quarantined("DANGER.EXAMPLE.TEST.") is True
    assert state.is_quarantined("safe.example.test") is False


def test_quarantine_state_lists_domains_sorted() -> None:
    state = QuarantineState()

    state.add(scored_result("quarantine", domain="zeta.example.test"))
    state.add(scored_result("quarantine", domain="alpha.example.test"))

    assert [
        entry["domain"] for entry in state.list_quarantined()
    ] == [
        "alpha.example.test",
        "zeta.example.test",
    ]


def test_quarantine_state_does_not_store_non_quarantine_actions() -> None:
    state = QuarantineState()

    state.add(scored_result("allow"))
    state.add(scored_result("log"))
    state.add(scored_result("alert"))
    state.add(scored_result("strong_alert"))

    assert state.list_quarantined() == []


def test_quarantine_state_clear_empties_list() -> None:
    state = QuarantineState()
    state.add(scored_result("quarantine"))

    state.clear()

    assert state.list_quarantined() == []
    assert state.is_quarantined("example.com") is False


def test_no_persistent_file_is_created(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    state = QuarantineState()

    apply_action(scored_result("quarantine"))
    state.add(scored_result("quarantine"))
    state.list_quarantined()
    state.clear()

    assert list(tmp_path.iterdir()) == []
