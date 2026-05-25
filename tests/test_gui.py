import logging
from pathlib import Path

from dns_sentry import gui
from dns_sentry.scoring import ThresholdConfig

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_gui_module_imports_without_running_window() -> None:
    assert callable(gui.run_gui)


def test_gui_default_threshold_is_four() -> None:
    assert gui.DEFAULT_GUI_THRESHOLD == 4.0


def test_gui_resolve_icon_path_when_icon_exists(
    monkeypatch, tmp_path: Path
) -> None:
    icon_path = tmp_path / "assets" / "dns-sentry.ico"
    icon_path.parent.mkdir()
    icon_path.write_bytes(b"icon")
    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    assert gui.resolve_icon_path() == icon_path


def test_gui_resolve_icon_path_when_icon_is_missing(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    assert gui.resolve_icon_path() is None


def test_gui_missing_icon_does_not_call_tk_iconbitmap(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeRoot:
        def iconbitmap(self, default: str) -> None:
            raise AssertionError("iconbitmap should not be called without icon")

    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    gui._apply_window_icon(FakeRoot())


def test_gui_taskbar_icon_helper_is_safe_outside_windows(monkeypatch) -> None:
    monkeypatch.setattr(gui.sys, "platform", "linux")

    gui._configure_windows_taskbar_icon()


class FakeFullscreenRoot:
    def __init__(self) -> None:
        self.fullscreen = False
        self.bindings = {}

    def attributes(self, name: str, value: bool | None = None) -> bool | None:
        assert name == "-fullscreen"

        if value is None:
            return self.fullscreen

        self.fullscreen = value
        return None

    def bind(self, sequence: str, callback: object) -> None:
        self.bindings[sequence] = callback


def test_fullscreen_helpers_toggle_and_exit() -> None:
    root = FakeFullscreenRoot()

    assert gui._toggle_fullscreen(root) == "break"
    assert root.fullscreen is True
    assert gui._exit_fullscreen(root) == "break"
    assert root.fullscreen is False


def test_fullscreen_shortcuts_are_bound() -> None:
    root = FakeFullscreenRoot()
    gui._bind_fullscreen_shortcuts(root)

    assert "<F11>" in root.bindings
    assert "<Escape>" in root.bindings
    assert root.bindings["<F11>"](None) == "break"
    assert root.fullscreen is True
    assert root.bindings["<Escape>"](None) == "break"
    assert root.fullscreen is False


def test_gui_log_handler_masks_webhook_values() -> None:
    log_queue: gui.Queue[str] = gui.Queue()
    handler = gui._GuiLogHandler(log_queue)
    record = logging.LogRecord(
        name="dns_sentry",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="webhook=%s",
        args=(TEST_WEBHOOK_URL,),
        exc_info=None,
    )

    handler.emit(record)

    output = log_queue.get_nowait()

    assert TEST_WEBHOOK_URL not in output
    assert "webhook=[redacted]" in output


def test_gui_log_handler_keeps_scoring_fields_and_masks_webhook() -> None:
    log_queue: gui.Queue[str] = gui.Queue()
    handler = gui._GuiLogHandler(log_queue)
    record = logging.LogRecord(
        name="dns_sentry",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=(
            "risk_score=%s severity=%s action=%s quarantined=%s "
            "containment_required=%s webhook=%s"
        ),
        args=(55, "Suspicious", "alert", True, False, TEST_WEBHOOK_URL),
        exc_info=None,
    )

    handler.emit(record)

    output = log_queue.get_nowait()

    assert "risk_score=55 severity=Suspicious action=alert" in output
    assert "quarantined=True containment_required=False" in output
    assert TEST_WEBHOOK_URL not in output
    assert "webhook=[redacted]" in output


class FakeTree:
    def __init__(self) -> None:
        self.items: dict[str, tuple[str, ...]] = {}

    def exists(self, item_id: str) -> bool:
        return item_id in self.items

    def insert(
        self,
        parent: str,
        index: str,
        iid: str,
        values: tuple[str, ...],
    ) -> None:
        self.items[iid] = values

    def item(self, item_id: str, values: tuple[str, ...]) -> None:
        self.items[item_id] = values

    def get_children(self) -> tuple[str, ...]:
        return tuple(self.items)

    def delete(self, item_id: str) -> None:
        del self.items[item_id]


def test_quarantine_entry_from_result_ignores_non_quarantined_result() -> None:
    state = gui.QuarantineState()

    entry = gui._quarantine_entry_from_result(
        state,
        {
            "domain": "safe.example.com",
            "risk_score": 0,
            "severity": "Safe",
            "action": "allow",
            "quarantined": False,
            "reasons": [],
        },
    )

    assert entry is None
    assert state.list_quarantined() == []


def test_quarantine_entry_can_be_added_to_view() -> None:
    state = gui.QuarantineState()
    tree = FakeTree()
    result = {
        "domain": "Danger.Example.TEST.",
        "risk_score": 80,
        "severity": "Dangerous",
        "action": "quarantine",
        "quarantined": True,
        "reasons": ["Logical quarantine test"],
    }

    entry = gui._quarantine_entry_from_result(state, result)
    assert entry is not None
    gui._upsert_quarantine_tree_item(tree, entry)

    assert state.is_quarantined("danger.example.test") is True
    assert "danger.example.test" in tree.items
    assert tree.items["danger.example.test"][:4] == (
        "danger.example.test",
        "80",
        "Dangerous",
        "quarantine",
    )
    assert TEST_WEBHOOK_URL not in str(tree.items)


def test_clear_quarantine_view_empties_state_and_tree() -> None:
    state = gui.QuarantineState()
    tree = FakeTree()
    result = {
        "domain": "danger.example.test",
        "risk_score": 80,
        "severity": "Dangerous",
        "action": "quarantine",
        "quarantined": True,
        "reasons": ["Logical quarantine test"],
    }
    entry = gui._quarantine_entry_from_result(state, result)
    assert entry is not None
    gui._upsert_quarantine_tree_item(tree, entry)

    gui._clear_quarantine_view(state, tree)

    assert state.list_quarantined() == []
    assert tree.items == {}


def test_parse_threshold_rejects_invalid_value() -> None:
    try:
        gui._parse_threshold("-1")
    except ValueError:
        pass
    else:
        raise AssertionError("negative threshold should fail")


def test_parse_risk_thresholds_accepts_valid_values() -> None:
    result = gui._parse_risk_thresholds("20", "40", "60", "80", "95")

    assert result == ThresholdConfig(
        low_suspicious_threshold=20,
        alert_threshold=40,
        strong_alert_threshold=60,
        quarantine_threshold=80,
        containment_threshold=95,
    )


def test_parse_risk_thresholds_rejects_incoherent_values() -> None:
    try:
        gui._parse_risk_thresholds("25", "45", "65", "40", "90")
    except ValueError as error:
        assert "invalid threshold order" in str(error)
    else:
        raise AssertionError("incoherent risk thresholds should fail")


def test_gui_exposes_risk_profile_options() -> None:
    assert gui.RISK_PROFILE_NAMES == (
        "personal",
        "balanced",
        "enterprise",
        "paranoid",
        "demo",
    )


def test_gui_profile_threshold_values_are_display_ready() -> None:
    profile_config = gui.get_threshold_config_for_profile("demo")

    assert gui._threshold_field_values(profile_config) == (
        "20",
        "35",
        "50",
        "65",
        "80",
    )


def test_gui_risk_profile_status_text() -> None:
    assert gui._risk_profile_status_text("enterprise") == "Risk profile: enterprise"


def test_parse_positive_limit_accepts_valid_value() -> None:
    assert gui._parse_positive_limit("20") == 20


def test_parse_positive_limit_rejects_zero() -> None:
    try:
        gui._parse_positive_limit("0")
    except ValueError as error:
        assert "limit must be at least 1" in str(error)
    else:
        raise AssertionError("zero events limit should fail")


def test_load_persistence_enabled_reads_environment(monkeypatch) -> None:
    monkeypatch.setattr(gui, "load_env_file", lambda: None)
    monkeypatch.setenv("ENABLE_PERSISTENCE", "true")

    assert gui._load_persistence_enabled() is True

    monkeypatch.setenv("ENABLE_PERSISTENCE", "false")

    assert gui._load_persistence_enabled() is False


def test_events_status_text_reports_disabled_or_database() -> None:
    assert "Persistence disabled" in gui._events_status_text(False, "events.db")
    assert gui._events_status_text(True, "events.db") == "Database: events.db"


def test_event_tree_values_include_expected_fields_without_secrets() -> None:
    values = gui._event_tree_values(
        {
            "id": 7,
            "timestamp": 123.5,
            "domain": "danger.example.test",
            "severity": "Dangerous",
            "action": "quarantine",
            "risk_score": 80,
            "source": "demo",
            "webhook_url": TEST_WEBHOOK_URL,
        }
    )

    assert values == (
        "7",
        "123.5",
        "danger.example.test",
        "Dangerous",
        "quarantine",
        "80",
        "demo",
    )
    assert TEST_WEBHOOK_URL not in str(values)


def test_populate_events_tree_replaces_existing_items_and_clear_tree() -> None:
    tree = FakeTree()
    tree.insert("", "end", iid="old", values=("old.example.test",))

    gui._populate_events_tree(
        tree,
        [
            {
                "id": 1,
                "timestamp": 10.0,
                "domain": "first.example.test",
                "severity": "Safe",
                "action": "allow",
                "risk_score": 0,
                "source": "demo",
            },
            {
                "id": 2,
                "timestamp": 20.0,
                "domain": "second.example.test",
                "severity": "Critical",
                "action": "quarantine_and_containment",
                "risk_score": 95,
                "source": "live",
            },
        ],
    )

    assert "old" not in tree.items
    assert tree.items["1"] == (
        "1",
        "10.0",
        "first.example.test",
        "Safe",
        "allow",
        "0",
        "demo",
    )
    assert tree.items["2"][2:5] == (
        "second.example.test",
        "Critical",
        "quarantine_and_containment",
    )

    gui._clear_tree(tree)

    assert tree.items == {}

