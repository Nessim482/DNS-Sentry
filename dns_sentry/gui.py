"""Minimal Tkinter GUI for DNS-Sentry."""

from __future__ import annotations

import logging
from pathlib import Path
from queue import Empty, Queue
import sys
from threading import Event, Thread
import tkinter as tk
from tkinter import scrolledtext, ttk

from .config import (
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
)
from .demo import run_demo
from .logging_config import LOGGER_NAME, mask_sensitive_text, setup_logging
from .sniffer import start_dns_sniffer

DEFAULT_GUI_THRESHOLD = 4.0
ICON_RELATIVE_PATH = Path("assets") / "dns-sentry.ico"
WINDOWS_APP_USER_MODEL_ID = "DNS-Sentry.Desktop"


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


def _resolve_webhook(entry_value: str) -> str | None:
    return _clean_optional_text(entry_value) or load_discord_webhook_url()


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


def _configure_gui_logging(log_queue: Queue[str], debug: bool) -> logging.Logger:
    logger = setup_logging(debug=debug)
    handler = _GuiLogHandler(log_queue)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)
    return logger


def run_gui() -> None:
    """Run the DNS-Sentry Tkinter dashboard."""
    _configure_windows_taskbar_icon()
    root = tk.Tk()
    root.title("DNS-Sentry")
    _apply_window_icon(root)
    root.geometry("820x560")
    root.minsize(720, 500)

    log_queue: Queue[str] = Queue()
    stop_event = Event()
    worker: Thread | None = None

    interface_var = tk.StringVar(value=load_dns_interface() or "")
    threshold_var = tk.StringVar(
        value=str(load_dns_entropy_threshold(default=DEFAULT_GUI_THRESHOLD))
    )
    webhook_var = tk.StringVar(value="")
    debug_var = tk.BooleanVar(value=load_dns_debug())
    status_var = tk.StringVar(value="Stopped")

    style = ttk.Style(root)
    style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
    style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"))

    main_frame = ttk.Frame(root, padding=12)
    main_frame.pack(fill=tk.BOTH, expand=True)
    main_frame.columnconfigure(0, weight=1)
    main_frame.rowconfigure(3, weight=1)

    ttk.Label(main_frame, text="DNS-Sentry", style="Title.TLabel").grid(
        row=0,
        column=0,
        sticky="w",
        pady=(0, 10),
    )

    config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding=10)
    config_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
    config_frame.columnconfigure(1, weight=1)

    ttk.Label(config_frame, text="Discord webhook").grid(row=0, column=0, sticky="w")
    webhook_entry = ttk.Entry(config_frame, textvariable=webhook_var, show="*")
    webhook_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=4)

    ttk.Label(config_frame, text="Network interface").grid(row=1, column=0, sticky="w")
    interface_entry = ttk.Entry(config_frame, textvariable=interface_var)
    interface_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)

    ttk.Label(config_frame, text="Entropy threshold").grid(row=2, column=0, sticky="w")
    threshold_entry = ttk.Entry(config_frame, textvariable=threshold_var, width=12)
    threshold_entry.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=4)

    ttk.Checkbutton(config_frame, text="Debug logging", variable=debug_var).grid(
        row=3,
        column=1,
        sticky="w",
        padx=(10, 0),
        pady=4,
    )

    controls_frame = ttk.LabelFrame(main_frame, text="Controls", padding=10)
    controls_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
    controls_frame.columnconfigure(3, weight=1)

    events_frame = ttk.LabelFrame(main_frame, text="Live Events", padding=10)
    events_frame.grid(row=3, column=0, sticky="nsew")
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
        height=16,
        state=tk.DISABLED,
        wrap=tk.WORD,
        font=("Consolas", 10),
    )
    log_text.grid(row=1, column=0, sticky="nsew")

    def append_log(message: str) -> None:
        log_text.configure(state=tk.NORMAL)
        log_text.insert(tk.END, f"{message}\n")
        log_text.see(tk.END)
        log_text.configure(state=tk.DISABLED)

    def drain_log_queue() -> None:
        while True:
            try:
                append_log(log_queue.get_nowait())
            except Empty:
                break

        root.after(100, drain_log_queue)

    def mark_stopped() -> None:
        update_status("Stopped")

    def current_threshold() -> float | None:
        logger = _configure_gui_logging(log_queue, debug_var.get())

        try:
            return _parse_threshold(threshold_var.get())
        except ValueError:
            logger.error("Invalid entropy threshold")
            return None

    def start_monitoring() -> None:
        nonlocal worker
        logger = _configure_gui_logging(log_queue, debug_var.get())

        if worker is not None and worker.is_alive():
            logger.info("Monitoring is already running")
            return

        threshold = current_threshold()

        if threshold is None:
            return

        interface = _clean_optional_text(interface_var.get())
        webhook_url = _resolve_webhook(webhook_var.get())
        stop_event.clear()
        update_status("Running")
        logger.info(
            "Starting GUI monitoring interface=%s threshold=%s debug=%s "
            "discord_webhook_configured=%s",
            interface or "auto",
            threshold,
            debug_var.get(),
            webhook_url is not None,
        )

        def monitor() -> None:
            try:
                start_dns_sniffer(
                    interface=interface,
                    webhook_url=webhook_url,
                    threshold=threshold,
                    debug=debug_var.get(),
                    stop_event=stop_event,
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

        if threshold is None:
            return

        webhook_url = _resolve_webhook(webhook_var.get())
        update_status("Running")
        logger.info(
            "Starting GUI demo threshold=%s debug=%s discord_webhook_configured=%s",
            threshold,
            debug_var.get(),
            webhook_url is not None,
        )

        def demo_worker() -> None:
            try:
                run_demo(threshold=threshold, webhook_url=webhook_url)
            except Exception as error:
                logger.error("%s", error)
            finally:
                root.after(0, mark_stopped)

        Thread(target=demo_worker, daemon=True).start()

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

    drain_log_queue()
    root.mainloop()

