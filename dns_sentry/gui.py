"""Minimal Tkinter GUI for DNS-Sentry."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from queue import Empty, Queue
import sys
from threading import Event, Thread
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from .config import (
    load_database_path,
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
    load_dns_risk_thresholds,
    load_env_file,
    load_risk_profile,
)
from .demo import run_demo
from .export import export_events_to_csv, export_events_to_json
from .logging_config import LOGGER_NAME, mask_sensitive_text, setup_logging
from .quarantine import QuarantineState
from .scoring import (
    RISK_PROFILE_NAMES,
    ThresholdConfig,
    get_threshold_config_for_profile,
    normalize_risk_profile_name,
    validate_thresholds,
)
from .sniffer import start_dns_sniffer
from .storage.sqlite import list_dns_events

DEFAULT_GUI_THRESHOLD = 4.0
ICON_RELATIVE_PATH = Path("assets") / "dns-sentry.ico"
WINDOWS_APP_USER_MODEL_ID = "DNS-Sentry.Desktop"
_TRUE_VALUES = {"1", "true", "yes", "on"}


class _GuiLogHandler(logging.Handler):
    def __init__(self, log_queue: Queue[str]) -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        message = mask_sensitive_text(record.getMessage())
        self.log_queue.put(f"[{record.levelname}] {message}")


def _clean_optional_text(value: str) -> str | None:
    cleaned_value = value.strip()
    return cleaned_value or None


def _parse_threshold(value: str) -> float:
    threshold = float(value.strip())

    if threshold < 0:
        raise ValueError("threshold must be non-negative")

    return threshold


def _parse_positive_limit(value: str) -> int:
    limit = int(value.strip())

    if limit < 1:
        raise ValueError("limit must be at least 1")

    return limit


def _parse_risk_thresholds(
    low_suspicious_threshold: str,
    alert_threshold: str,
    strong_alert_threshold: str,
    quarantine_threshold: str,
    containment_threshold: str,
) -> ThresholdConfig:
    try:
        threshold_config = ThresholdConfig(
            low_suspicious_threshold=int(low_suspicious_threshold.strip()),
            alert_threshold=int(alert_threshold.strip()),
            strong_alert_threshold=int(strong_alert_threshold.strip()),
            quarantine_threshold=int(quarantine_threshold.strip()),
            containment_threshold=int(containment_threshold.strip()),
        )
    except ValueError as error:
        raise ValueError("risk thresholds must be integers") from error

    validate_thresholds(threshold_config)
    return threshold_config


def _threshold_field_values(config: ThresholdConfig) -> tuple[str, str, str, str, str]:
    return (
        str(config.low_suspicious_threshold),
        str(config.alert_threshold),
        str(config.strong_alert_threshold),
        str(config.quarantine_threshold),
        str(config.containment_threshold),
    )


def _risk_profile_status_text(profile_name: str) -> str:
    return f"Risk profile: {profile_name}"


def _resolve_webhook(entry_value: str) -> str | None:
    return _clean_optional_text(entry_value) or load_discord_webhook_url()


def _load_persistence_enabled() -> bool:
    load_env_file()
    value = os.getenv("ENABLE_PERSISTENCE")

    if value is None:
        return False

    return value.strip().lower() in _TRUE_VALUES


def _events_status_text(persistence_enabled: bool, database_path: str) -> str:
    if not persistence_enabled:
        return "Persistence disabled. Stored events are not being written."

    return f"Database: {database_path}"


def _event_tree_values(event: dict) -> tuple[str, str, str, str, str, str, str]:
    return (
        _format_quarantine_value(event.get("id")),
        _format_quarantine_value(event.get("timestamp")),
        _format_quarantine_value(event.get("domain")),
        _format_quarantine_value(event.get("severity")),
        _format_quarantine_value(event.get("action")),
        _format_quarantine_value(event.get("risk_score")),
        _format_quarantine_value(event.get("source")),
    )


def _clear_tree(tree: object) -> None:
    for item_id in list(getattr(tree, "get_children")()):
        getattr(tree, "delete")(item_id)


def _populate_events_tree(tree: object, events: list[dict]) -> None:
    _clear_tree(tree)

    for event in events:
        item_id = str(event.get("id", event.get("domain", "")))
        getattr(tree, "insert")("", "end", iid=item_id, values=_event_tree_values(event))


def _project_root() -> Path:
    bundle_path = getattr(sys, "_MEIPASS", None)
    if bundle_path:
        return Path(bundle_path)

    return Path(__file__).resolve().parent.parent


def resolve_icon_path() -> Path | None:
    icon_path = _project_root() / ICON_RELATIVE_PATH
    if icon_path.is_file():
        return icon_path

    return None


def _apply_window_icon(root: tk.Tk) -> None:
    icon_path = resolve_icon_path()
    if icon_path is None:
        return

    try:
        root.iconbitmap(default=str(icon_path))
    except tk.TclError:
        return


def _configure_windows_taskbar_icon() -> None:
    if sys.platform != "win32":
        return

    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            WINDOWS_APP_USER_MODEL_ID
        )
    except (AttributeError, OSError):
        return


def _is_fullscreen(root: object) -> bool:
    return bool(getattr(root, "attributes")("-fullscreen"))


def _set_fullscreen(root: object, enabled: bool) -> None:
    getattr(root, "attributes")("-fullscreen", enabled)


def _toggle_fullscreen(root: object) -> str:
    _set_fullscreen(root, not _is_fullscreen(root))
    return "break"


def _exit_fullscreen(root: object) -> str:
    _set_fullscreen(root, False)
    return "break"


def _bind_fullscreen_shortcuts(root: object) -> None:
    getattr(root, "bind")("<F11>", lambda _event: _toggle_fullscreen(root))
    getattr(root, "bind")("<Escape>", lambda _event: _exit_fullscreen(root))


def _configure_gui_logging(log_queue: Queue[str], debug: bool) -> logging.Logger:
    logger = setup_logging(debug=debug)
    handler = _GuiLogHandler(log_queue)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)
    return logger


def _format_quarantine_value(value: object) -> str:
    if value is None:
        return "N/A"

    return str(value)


def _quarantine_entry_from_result(
    quarantine_state: QuarantineState,
    result: dict,
) -> dict | None:
    if not result.get("quarantined"):
        return None

    quarantine_state.add(result)
    domain = str(result["domain"]).strip().rstrip(".").lower()

    for entry in quarantine_state.list_quarantined():
        if entry["domain"] == domain:
            return entry

    return None


def _quarantine_tree_values(entry: dict) -> tuple[str, str, str, str, str]:
    return (
        _format_quarantine_value(entry.get("domain")),
        _format_quarantine_value(entry.get("risk_score")),
        _format_quarantine_value(entry.get("severity")),
        _format_quarantine_value(entry.get("action")),
        _format_quarantine_value(entry.get("timestamp")),
    )


def _upsert_quarantine_tree_item(tree: object, entry: dict) -> None:
    item_id = str(entry["domain"])
    values = _quarantine_tree_values(entry)
    exists = getattr(tree, "exists")(item_id)

    if exists:
        getattr(tree, "item")(item_id, values=values)
        return

    getattr(tree, "insert")("", "end", iid=item_id, values=values)


def _clear_quarantine_view(quarantine_state: QuarantineState, tree: object) -> None:
    quarantine_state.clear()

    for item_id in list(getattr(tree, "get_children")()):
        getattr(tree, "delete")(item_id)


def run_gui(
    threshold_config: ThresholdConfig | None = None,
    risk_profile: str | None = None,
) -> None:
    """Run the DNS-Sentry Tkinter dashboard."""
    _configure_windows_taskbar_icon()
    root = tk.Tk()
    root.title("DNS-Sentry")
    _apply_window_icon(root)
    _bind_fullscreen_shortcuts(root)
    root.geometry("980x720")
    root.minsize(840, 620)

    log_queue: Queue[str] = Queue()
    quarantine_queue: Queue[dict] = Queue()
    quarantine_state = QuarantineState()
    stop_event = Event()
    worker: Thread | None = None

    interface_var = tk.StringVar(value=load_dns_interface() or "")
    if risk_profile is None:
        initial_risk_profile = load_risk_profile()
    else:
        initial_risk_profile = normalize_risk_profile_name(risk_profile)
        get_threshold_config_for_profile(initial_risk_profile)
    initial_threshold_config = threshold_config or load_dns_risk_thresholds(
        profile_name=initial_risk_profile
    )
    threshold_var = tk.StringVar(
        value=str(load_dns_entropy_threshold(default=DEFAULT_GUI_THRESHOLD))
    )
    low_suspicious_threshold_var = tk.StringVar(
        value=str(initial_threshold_config.low_suspicious_threshold)
    )
    alert_threshold_var = tk.StringVar(
        value=str(initial_threshold_config.alert_threshold)
    )
    strong_alert_threshold_var = tk.StringVar(
        value=str(initial_threshold_config.strong_alert_threshold)
    )
    quarantine_threshold_var = tk.StringVar(
        value=str(initial_threshold_config.quarantine_threshold)
    )
    containment_threshold_var = tk.StringVar(
        value=str(initial_threshold_config.containment_threshold)
    )
    risk_profile_var = tk.StringVar(value=initial_risk_profile)
    active_profile_var = tk.StringVar(
        value=_risk_profile_status_text(initial_risk_profile)
    )
    webhook_var = tk.StringVar(value="")
    debug_var = tk.BooleanVar(value=load_dns_debug())
    status_var = tk.StringVar(value="Stopped")
    persistence_enabled = _load_persistence_enabled()
    database_path = load_database_path()
    events_limit_var = tk.StringVar(value="100")
    events_severity_var = tk.StringVar(value="")
    events_action_var = tk.StringVar(value="")
    events_status_var = tk.StringVar(
        value=_events_status_text(persistence_enabled, database_path)
    )

    style = ttk.Style(root)
    style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
    style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"))

    main_frame = ttk.Frame(root, padding=12)
    main_frame.pack(fill=tk.BOTH, expand=True)
    main_frame.columnconfigure(0, weight=1)
    main_frame.rowconfigure(1, weight=1)

    ttk.Label(main_frame, text="DNS-Sentry", style="Title.TLabel").grid(
        row=0,
        column=0,
        sticky="w",
        pady=(0, 10),
    )

    notebook = ttk.Notebook(main_frame)
    notebook.grid(row=1, column=0, sticky="nsew")

    monitoring_tab = ttk.Frame(notebook, padding=10)
    risk_tab = ttk.Frame(notebook, padding=10)
    quarantine_tab = ttk.Frame(notebook, padding=10)
    events_tab = ttk.Frame(notebook, padding=10)
    about_tab = ttk.Frame(notebook, padding=10)

    notebook.add(monitoring_tab, text="Monitoring")
    notebook.add(risk_tab, text="Risk Policy")
    notebook.add(quarantine_tab, text="Quarantine")
    notebook.add(events_tab, text="Events")
    notebook.add(about_tab, text="About / Status")

    monitoring_tab.columnconfigure(0, weight=1)
    monitoring_tab.rowconfigure(2, weight=1)
    risk_tab.columnconfigure(0, weight=1)
    quarantine_tab.columnconfigure(0, weight=1)
    quarantine_tab.rowconfigure(0, weight=1)
    events_tab.columnconfigure(0, weight=1)
    events_tab.rowconfigure(0, weight=1)
    about_tab.columnconfigure(0, weight=1)

    config_frame = ttk.LabelFrame(monitoring_tab, text="Configuration", padding=10)
    config_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    config_frame.columnconfigure(0, weight=3)
    config_frame.columnconfigure(1, weight=1)

    general_frame = ttk.Frame(config_frame)
    general_frame.grid(row=0, column=0, sticky="nsew")
    general_frame.columnconfigure(1, weight=1)

    risk_frame = ttk.LabelFrame(risk_tab, text="Risk Thresholds", padding=(8, 6))
    risk_frame.grid(row=0, column=0, sticky="ew")
    risk_frame.columnconfigure(1, weight=1)
    risk_frame.columnconfigure(3, weight=1)

    ttk.Label(general_frame, text="Discord webhook").grid(row=0, column=0, sticky="w")
    webhook_entry = ttk.Entry(general_frame, textvariable=webhook_var, show="*")
    webhook_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=3)

    ttk.Label(general_frame, text="Network interface").grid(
        row=1,
        column=0,
        sticky="w",
    )
    interface_entry = ttk.Entry(general_frame, textvariable=interface_var)
    interface_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=3)

    ttk.Label(general_frame, text="Entropy threshold").grid(
        row=2,
        column=0,
        sticky="w",
    )
    threshold_entry = ttk.Entry(general_frame, textvariable=threshold_var, width=10)
    threshold_entry.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=3)

    ttk.Checkbutton(general_frame, text="Debug logging", variable=debug_var).grid(
        row=3,
        column=1,
        sticky="w",
        padx=(10, 0),
        pady=3,
    )

    ttk.Label(risk_frame, text="Profile").grid(row=0, column=0, sticky="w")
    risk_profile_select = ttk.Combobox(
        risk_frame,
        textvariable=risk_profile_var,
        values=RISK_PROFILE_NAMES,
        state="readonly",
        width=16,
    )
    risk_profile_select.grid(
        row=0,
        column=1,
        sticky="w",
        padx=(8, 12),
        pady=3,
    )
    ttk.Label(risk_frame, textvariable=active_profile_var).grid(
        row=0,
        column=2,
        columnspan=2,
        sticky="w",
        padx=(8, 0),
        pady=3,
    )

    ttk.Label(risk_frame, text="Low suspicious").grid(row=1, column=0, sticky="w")
    ttk.Entry(
        risk_frame,
        textvariable=low_suspicious_threshold_var,
        width=8,
    ).grid(row=1, column=1, sticky="w", padx=(8, 12), pady=3)

    ttk.Label(risk_frame, text="Alert").grid(row=1, column=2, sticky="w")
    ttk.Entry(risk_frame, textvariable=alert_threshold_var, width=8).grid(
        row=1,
        column=3,
        sticky="w",
        padx=(8, 0),
        pady=3,
    )

    ttk.Label(risk_frame, text="Strong alert").grid(
        row=2,
        column=0,
        sticky="w",
    )
    ttk.Entry(risk_frame, textvariable=strong_alert_threshold_var, width=8).grid(
        row=2,
        column=1,
        sticky="w",
        padx=(8, 12),
        pady=3,
    )

    ttk.Label(risk_frame, text="Quarantine").grid(
        row=2,
        column=2,
        sticky="w",
    )
    ttk.Entry(risk_frame, textvariable=quarantine_threshold_var, width=8).grid(
        row=2,
        column=3,
        sticky="w",
        padx=(8, 0),
        pady=3,
    )

    ttk.Label(risk_frame, text="Containment").grid(
        row=3,
        column=0,
        sticky="w",
    )
    ttk.Entry(risk_frame, textvariable=containment_threshold_var, width=8).grid(
        row=3,
        column=1,
        sticky="w",
        padx=(8, 12),
        pady=3,
    )

    controls_frame = ttk.LabelFrame(monitoring_tab, text="Controls", padding=10)
    controls_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
    controls_frame.columnconfigure(3, weight=1)

    events_frame = ttk.LabelFrame(monitoring_tab, text="Live Events", padding=10)
    events_frame.grid(row=2, column=0, sticky="nsew")
    events_frame.columnconfigure(0, weight=1)
    events_frame.rowconfigure(1, weight=1)

    status_label = ttk.Label(events_frame, style="Status.TLabel")
    status_label.grid(row=0, column=0, sticky="w", pady=(0, 8))

    def update_status(value: str) -> None:
        status_var.set(value)
        status_label.configure(text=f"Status: {value}")

    update_status("Stopped")

    log_text = scrolledtext.ScrolledText(
        events_frame,
        height=14,
        state=tk.DISABLED,
        wrap=tk.WORD,
        font=("Consolas", 10),
    )
    log_text.grid(row=1, column=0, sticky="nsew")

    quarantine_frame = ttk.LabelFrame(quarantine_tab, text="Quarantine", padding=10)
    quarantine_frame.grid(row=0, column=0, sticky="nsew")
    quarantine_frame.columnconfigure(0, weight=1)
    quarantine_frame.rowconfigure(1, weight=1)

    stored_events_frame = ttk.LabelFrame(events_tab, text="Stored Events", padding=10)
    stored_events_frame.grid(row=0, column=0, sticky="nsew")
    stored_events_frame.columnconfigure(0, weight=1)
    stored_events_frame.rowconfigure(2, weight=1)

    events_controls_frame = ttk.Frame(stored_events_frame)
    events_controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
    events_controls_frame.columnconfigure(7, weight=1)

    ttk.Label(events_controls_frame, text="Limit").grid(row=0, column=0, sticky="w")
    events_limit_entry = ttk.Entry(
        events_controls_frame,
        textvariable=events_limit_var,
        width=8,
    )
    events_limit_entry.grid(row=0, column=1, sticky="w", padx=(6, 12))

    ttk.Label(events_controls_frame, text="Severity").grid(row=0, column=2, sticky="w")
    events_severity_entry = ttk.Entry(
        events_controls_frame,
        textvariable=events_severity_var,
        width=16,
    )
    events_severity_entry.grid(row=0, column=3, sticky="w", padx=(6, 12))

    ttk.Label(events_controls_frame, text="Action").grid(row=0, column=4, sticky="w")
    events_action_entry = ttk.Entry(
        events_controls_frame,
        textvariable=events_action_var,
        width=18,
    )
    events_action_entry.grid(row=0, column=5, sticky="w", padx=(6, 12))

    refresh_events_button = ttk.Button(events_controls_frame, text="Refresh")
    refresh_events_button.grid(row=0, column=6, sticky="w", padx=(0, 8))
    export_json_button = ttk.Button(events_controls_frame, text="Export JSON")
    export_json_button.grid(row=0, column=8, sticky="e", padx=(8, 0))
    export_csv_button = ttk.Button(events_controls_frame, text="Export CSV")
    export_csv_button.grid(row=0, column=9, sticky="e", padx=(8, 0))

    ttk.Label(stored_events_frame, textvariable=events_status_var).grid(
        row=1,
        column=0,
        sticky="w",
        pady=(0, 8),
    )

    events_tree = ttk.Treeview(
        stored_events_frame,
        columns=("id", "timestamp", "domain", "severity", "action", "risk_score", "source"),
        show="headings",
        height=12,
    )
    events_tree.heading("id", text="ID")
    events_tree.heading("timestamp", text="Timestamp")
    events_tree.heading("domain", text="Domain")
    events_tree.heading("severity", text="Severity")
    events_tree.heading("action", text="Action")
    events_tree.heading("risk_score", text="Risk Score")
    events_tree.heading("source", text="Source")
    events_tree.column("id", width=60, anchor="center")
    events_tree.column("timestamp", width=140, anchor="center")
    events_tree.column("domain", width=260, anchor="w")
    events_tree.column("severity", width=120, anchor="center")
    events_tree.column("action", width=170, anchor="center")
    events_tree.column("risk_score", width=90, anchor="center")
    events_tree.column("source", width=100, anchor="center")
    events_tree.grid(row=2, column=0, sticky="nsew")

    status_frame = ttk.LabelFrame(about_tab, text="Status", padding=10)
    status_frame.grid(row=0, column=0, sticky="ew")
    status_frame.columnconfigure(0, weight=1)
    ttk.Label(
        status_frame,
        text=f"Persistence: {'enabled' if persistence_enabled else 'disabled'}",
    ).grid(row=0, column=0, sticky="w", pady=2)
    ttk.Label(status_frame, textvariable=active_profile_var).grid(
        row=1,
        column=0,
        sticky="w",
        pady=2,
    )
    ttk.Label(status_frame, text=f"Database path: {database_path}").grid(
        row=2,
        column=0,
        sticky="w",
        pady=2,
    )
    ttk.Label(
        status_frame,
        text="Npcap required on Windows for live monitoring",
    ).grid(row=3, column=0, sticky="w", pady=2)

    quarantine_tree = ttk.Treeview(
        quarantine_frame,
        columns=("domain", "risk_score", "severity", "action", "timestamp"),
        show="headings",
        height=6,
    )
    quarantine_tree.heading("domain", text="Domain")
    quarantine_tree.heading("risk_score", text="Risk Score")
    quarantine_tree.heading("severity", text="Severity")
    quarantine_tree.heading("action", text="Action")
    quarantine_tree.heading("timestamp", text="Timestamp")
    quarantine_tree.column("domain", width=260, anchor="w")
    quarantine_tree.column("risk_score", width=80, anchor="center")
    quarantine_tree.column("severity", width=120, anchor="center")
    quarantine_tree.column("action", width=170, anchor="center")
    quarantine_tree.column("timestamp", width=140, anchor="center")
    quarantine_tree.grid(row=1, column=0, sticky="nsew")

    def append_log(message: str) -> None:
        log_text.configure(state=tk.NORMAL)
        log_text.insert(tk.END, f"{message}\n")
        log_text.see(tk.END)
        log_text.configure(state=tk.DISABLED)

    def enqueue_runtime_result(result: dict) -> None:
        if result.get("quarantined"):
            quarantine_queue.put(dict(result))

    def append_quarantine_result(result: dict) -> None:
        entry = _quarantine_entry_from_result(quarantine_state, result)
        if entry is not None:
            _upsert_quarantine_tree_item(quarantine_tree, entry)

    def drain_log_queue() -> None:
        while True:
            try:
                append_log(log_queue.get_nowait())
            except Empty:
                break

        root.after(100, drain_log_queue)

    def drain_quarantine_queue() -> None:
        while True:
            try:
                append_quarantine_result(quarantine_queue.get_nowait())
            except Empty:
                break

        root.after(100, drain_quarantine_queue)

    def clear_quarantine() -> None:
        _clear_quarantine_view(quarantine_state, quarantine_tree)
        _configure_gui_logging(log_queue, debug_var.get()).info(
            "Logical quarantine view cleared"
        )

    def mark_stopped() -> None:
        update_status("Stopped")

    def current_threshold() -> float | None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        try:
            return _parse_threshold(threshold_var.get())
        except ValueError:
            logger.error("Invalid entropy threshold")
            return None

    def current_threshold_config() -> ThresholdConfig | None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        try:
            return _parse_risk_thresholds(
                low_suspicious_threshold_var.get(),
                alert_threshold_var.get(),
                strong_alert_threshold_var.get(),
                quarantine_threshold_var.get(),
                containment_threshold_var.get(),
            )
        except ValueError as error:
            logger.error("Invalid risk thresholds: %s", error)
            return None

    def apply_risk_profile(profile_name: str) -> None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        try:
            normalized_profile = normalize_risk_profile_name(profile_name)
            profile_thresholds = get_threshold_config_for_profile(normalized_profile)
        except ValueError as error:
            logger.error("Invalid risk profile: %s", error)
            return

        (
            low_suspicious,
            alert,
            strong_alert,
            quarantine,
            containment,
        ) = _threshold_field_values(profile_thresholds)
        low_suspicious_threshold_var.set(low_suspicious)
        alert_threshold_var.set(alert)
        strong_alert_threshold_var.set(strong_alert)
        quarantine_threshold_var.set(quarantine)
        containment_threshold_var.set(containment)
        risk_profile_var.set(normalized_profile)
        active_profile_var.set(_risk_profile_status_text(normalized_profile))
        logger.info("Risk profile selected risk_profile=%s", normalized_profile)

    def start_monitoring() -> None:
        nonlocal worker
        logger = _configure_gui_logging(log_queue, debug_var.get())

        if worker is not None and worker.is_alive():
            logger.info("Monitoring is already running")
            return

        threshold = current_threshold()
        risk_thresholds = current_threshold_config()

        if threshold is None or risk_thresholds is None:
            return

        interface = _clean_optional_text(interface_var.get())
        webhook_url = _resolve_webhook(webhook_var.get())
        stop_event.clear()
        update_status("Running")
        logger.info(
            "Starting GUI monitoring interface=%s threshold=%s debug=%s "
            "discord_webhook_configured=%s risk_profile=%s risk_thresholds=%s",
            interface or "auto",
            threshold,
            debug_var.get(),
            webhook_url is not None,
            risk_profile_var.get(),
            risk_thresholds,
        )

        def monitor() -> None:
            try:
                start_dns_sniffer(
                    interface=interface,
                    webhook_url=webhook_url,
                    threshold=threshold,
                    threshold_config=risk_thresholds,
                    debug=debug_var.get(),
                    stop_event=stop_event,
                    result_callback=enqueue_runtime_result,
                )
            except Exception as error:
                logger.error("%s", error)
            finally:
                root.after(0, mark_stopped)

        worker = Thread(target=monitor, daemon=True)
        worker.start()

    def stop_monitoring() -> None:
        _configure_gui_logging(log_queue, debug_var.get()).info("Stop requested")
        stop_event.set()
        update_status("Stopped")

    def run_demo_from_gui() -> None:
        logger = _configure_gui_logging(log_queue, debug_var.get())
        threshold = current_threshold()
        risk_thresholds = current_threshold_config()

        if threshold is None or risk_thresholds is None:
            return

        webhook_url = _resolve_webhook(webhook_var.get())
        update_status("Running")
        logger.info(
            "Starting GUI demo threshold=%s debug=%s "
            "discord_webhook_configured=%s risk_profile=%s risk_thresholds=%s",
            threshold,
            debug_var.get(),
            webhook_url is not None,
            risk_profile_var.get(),
            risk_thresholds,
        )

        def demo_worker() -> None:
            try:
                run_demo(
                    threshold=threshold,
                    webhook_url=webhook_url,
                    result_callback=enqueue_runtime_result,
                    threshold_config=risk_thresholds,
                )
            except Exception as error:
                logger.error("%s", error)
            finally:
                root.after(0, mark_stopped)

        Thread(target=demo_worker, daemon=True).start()

    def current_events_query() -> tuple[int, str | None, str | None] | None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        try:
            limit = _parse_positive_limit(events_limit_var.get())
        except ValueError:
            logger.error("Invalid events limit")
            return None

        return (
            limit,
            _clean_optional_text(events_severity_var.get()),
            _clean_optional_text(events_action_var.get()),
        )

    def refresh_events() -> list[dict]:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        if not persistence_enabled:
            _clear_tree(events_tree)
            events_status_var.set(_events_status_text(False, database_path))
            return []

        query = current_events_query()
        if query is None:
            return []

        limit, severity_filter, action_filter = query

        try:
            events = list_dns_events(
                database_path,
                limit=limit,
                severity=severity_filter,
                action=action_filter,
            )
        except Exception as error:
            logger.error("Could not load stored DNS events: %s", error)
            return []

        _populate_events_tree(events_tree, events)
        events_status_var.set(f"{len(events)} stored event(s) loaded")
        return events

    def export_events(export_format: str) -> None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        if not persistence_enabled:
            events_status_var.set(_events_status_text(False, database_path))
            return

        events = refresh_events()
        extension = f".{export_format}"
        output_path = filedialog.asksaveasfilename(
            defaultextension=extension,
            filetypes=[(f"{export_format.upper()} files", f"*{extension}")],
        )

        if not output_path:
            return

        try:
            if export_format == "json":
                export_events_to_json(events, output_path)
            else:
                export_events_to_csv(events, output_path)
        except (OSError, ValueError) as error:
            logger.error("Could not export stored DNS events: %s", error)
            return

        events_status_var.set(f"Exported {len(events)} event(s)")

    ttk.Button(
        controls_frame,
        text="Start Monitoring",
        command=start_monitoring,
    ).grid(
        row=0,
        column=0,
        padx=(0, 8),
        sticky="w",
    )
    ttk.Button(controls_frame, text="Stop", command=stop_monitoring).grid(
        row=0,
        column=1,
        padx=(0, 8),
        sticky="w",
    )
    ttk.Button(controls_frame, text="Run Demo", command=run_demo_from_gui).grid(
        row=0,
        column=2,
        padx=(0, 8),
        sticky="w",
    )
    ttk.Label(controls_frame, text="Status:").grid(
        row=0,
        column=3,
        sticky="e",
    )
    ttk.Label(controls_frame, textvariable=status_var, style="Status.TLabel").grid(
        row=0,
        column=4,
        sticky="e",
        padx=(6, 0),
    )
    ttk.Button(
        quarantine_frame,
        text="Clear Quarantine",
        command=clear_quarantine,
    ).grid(
        row=0,
        column=0,
        sticky="e",
        pady=(0, 8),
    )
    refresh_events_button.configure(command=refresh_events)
    export_json_button.configure(command=lambda: export_events("json"))
    export_csv_button.configure(command=lambda: export_events("csv"))
    risk_profile_select.bind(
        "<<ComboboxSelected>>",
        lambda _event: apply_risk_profile(risk_profile_var.get()),
    )

    drain_log_queue()
    drain_quarantine_queue()
    root.mainloop()

