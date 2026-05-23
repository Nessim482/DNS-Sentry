"""Minimal Tkinter GUI for DNS-Sentry."""

from __future__ import annotations

import logging
from queue import Empty, Queue
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


def _configure_gui_logging(log_queue: Queue[str], debug: bool) -> logging.Logger:
    logger = setup_logging(debug=debug)
    handler = _GuiLogHandler(log_queue)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)
    return logger


def run_gui() -> None:
    """Run the DNS-Sentry Tkinter dashboard."""
    root = tk.Tk()
    root.title("DNS-Sentry")
    root.geometry("760x520")

    log_queue: Queue[str] = Queue()
    stop_event = Event()
    worker: Thread | None = None

    interface_var = tk.StringVar(value=load_dns_interface() or "")
    threshold_var = tk.StringVar(value=str(load_dns_entropy_threshold()))
    webhook_var = tk.StringVar(value="")
    debug_var = tk.BooleanVar(value=load_dns_debug())
    status_var = tk.StringVar(value="Stopped")

    main_frame = ttk.Frame(root, padding=12)
    main_frame.pack(fill=tk.BOTH, expand=True)
    main_frame.columnconfigure(1, weight=1)
    main_frame.rowconfigure(6, weight=1)

    ttk.Label(main_frame, text="Discord webhook").grid(row=0, column=0, sticky="w")
    webhook_entry = ttk.Entry(main_frame, textvariable=webhook_var, show="*")
    webhook_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)

    ttk.Label(main_frame, text="Interface").grid(row=1, column=0, sticky="w")
    interface_entry = ttk.Entry(main_frame, textvariable=interface_var)
    interface_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)

    ttk.Label(main_frame, text="Entropy threshold").grid(row=2, column=0, sticky="w")
    threshold_entry = ttk.Entry(main_frame, textvariable=threshold_var)
    threshold_entry.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=4)

    ttk.Checkbutton(main_frame, text="Debug", variable=debug_var).grid(
        row=3,
        column=1,
        sticky="w",
        padx=(8, 0),
        pady=4,
    )

    controls = ttk.Frame(main_frame)
    controls.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 4))

    status_label = ttk.Label(main_frame, textvariable=status_var)
    status_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=(0, 8))

    log_text = scrolledtext.ScrolledText(main_frame, height=18, state=tk.DISABLED)
    log_text.grid(row=6, column=0, columnspan=2, sticky="nsew")

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
        status_var.set("Stopped")

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
        status_var.set("Running")
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
        status_var.set("Stopped")

    def run_demo_from_gui() -> None:
        logger = _configure_gui_logging(log_queue, debug_var.get())
        threshold = current_threshold()

        if threshold is None:
            return

        webhook_url = _resolve_webhook(webhook_var.get())
        status_var.set("Running")
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

    ttk.Button(controls, text="Start Monitoring", command=start_monitoring).pack(
        side=tk.LEFT,
        padx=(0, 8),
    )
    ttk.Button(controls, text="Stop", command=stop_monitoring).pack(
        side=tk.LEFT,
        padx=(0, 8),
    )
    ttk.Button(controls, text="Run Demo", command=run_demo_from_gui).pack(side=tk.LEFT)

    drain_log_queue()
    root.mainloop()

