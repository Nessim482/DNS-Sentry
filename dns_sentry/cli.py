"""Command-line entrypoint for DNS-Sentry."""

import argparse
from collections.abc import Sequence
import importlib.util

from .config import (
    load_database_path,
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
    load_dns_risk_thresholds,
    load_env_file,
)
from .demo import run_demo
from .export import export_events_to_csv, export_events_to_json
from .gui import run_gui
from .logging_config import setup_logging
from .sniffer import start_dns_sniffer
from .storage.sqlite import list_dns_events

_CHECK_ENV_MODULES = {
    "Scapy": "scapy",
    "requests": "requests",
    "python-dotenv": "dotenv",
}


def _non_negative_float(value: str) -> float:
    try:
        threshold = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a float") from error

    if threshold < 0:
        raise argparse.ArgumentTypeError("must be non-negative")

    return threshold


def _risk_threshold_int(value: str) -> int:
    try:
        threshold = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if threshold < 0 or threshold > 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")

    return threshold


def _positive_int(value: str) -> int:
    try:
        parsed_value = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if parsed_value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")

    return parsed_value


def _non_empty_text(value: str) -> str:
    cleaned_value = value.strip()

    if not cleaned_value:
        raise argparse.ArgumentTypeError("must not be empty")

    return cleaned_value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-sentry",
        description="Minimal DNS tunneling detector.",
    )
    parser.add_argument("--interface", help="network interface to sniff")
    parser.add_argument(
        "--threshold",
        type=_non_negative_float,
        help="entropy threshold for suspicious domains",
    )
    parser.add_argument(
        "--low-suspicious-threshold",
        type=_risk_threshold_int,
        help="risk score threshold for Low Suspicious/log",
    )
    parser.add_argument(
        "--alert-threshold",
        type=_risk_threshold_int,
        help="risk score threshold for Suspicious/alert",
    )
    parser.add_argument(
        "--strong-alert-threshold",
        type=_risk_threshold_int,
        help="risk score threshold for High Risk/strong_alert",
    )
    parser.add_argument(
        "--quarantine-threshold",
        type=_risk_threshold_int,
        help="risk score threshold for Dangerous/quarantine",
    )
    parser.add_argument(
        "--containment-threshold",
        type=_risk_threshold_int,
        help="risk score threshold for Critical/quarantine_and_containment",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=None,
        help="enable debug output",
    )
    parser.add_argument("--webhook", help="Discord webhook URL")
    parser.add_argument(
        "--history",
        action="store_true",
        help="show stored DNS event history without sniffing",
    )
    parser.add_argument(
        "--export",
        choices=("json", "csv"),
        help="export stored DNS events without sniffing",
    )
    parser.add_argument(
        "--output",
        type=_non_empty_text,
        help="output path for --export",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=100,
        help="maximum number of stored events to read",
    )
    parser.add_argument(
        "--filter-severity",
        help="filter stored events by severity",
    )
    parser.add_argument(
        "--filter-action",
        help="filter stored events by action",
    )
    parser.add_argument(
        "--database-path",
        type=_non_empty_text,
        help="SQLite database path for history/export",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run simulated demo mode without network sniffing",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="run the minimal Tkinter desktop interface",
    )
    parser.add_argument(
        "--check-env",
        action="store_true",
        help="check dependencies and configuration without sniffing",
    )

    return parser


def _is_module_importable(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def check_environment() -> bool:
    """Check runtime dependencies and config loading without network sniffing."""
    logger = setup_logging()
    ok = True

    for label, module_name in _CHECK_ENV_MODULES.items():
        if _is_module_importable(module_name):
            logger.info("%s importable", label)
        else:
            logger.error("%s is not importable", label)
            ok = False

    try:
        load_env_file()
        load_discord_webhook_url()
        load_dns_entropy_threshold()
        load_dns_interface()
        load_dns_risk_thresholds()
        load_database_path()
        load_dns_debug()
        build_parser()
    except (OSError, ValueError) as error:
        logger.error("Environment check failed: %s", error)
        ok = False
    else:
        logger.info("Configuration loadable")
        logger.info("CLI functional")

    return ok


def _risk_threshold_overrides(args: argparse.Namespace) -> dict[str, int]:
    overrides = {}

    for field_name in (
        "low_suspicious_threshold",
        "alert_threshold",
        "strong_alert_threshold",
        "quarantine_threshold",
        "containment_threshold",
    ):
        value = getattr(args, field_name)

        if value is not None:
            overrides[field_name] = value

    return overrides


def _load_history_events(args: argparse.Namespace) -> list[dict]:
    database_path = (
        args.database_path if args.database_path is not None else load_database_path()
    )
    return list_dns_events(
        database_path,
        limit=args.limit,
        severity=args.filter_severity,
        action=args.filter_action,
    )


def _print_history(events: list[dict]) -> None:
    if not events:
        print("No DNS events found")
        return

    print("id\ttimestamp\tdomain\tseverity\taction\trisk_score")
    for event in events:
        print(
            "{id}\t{timestamp}\t{domain}\t{severity}\t{action}\t{risk_score}".format(
                id=event.get("id", ""),
                timestamp=event.get("timestamp", ""),
                domain=event.get("domain", ""),
                severity=event.get("severity", ""),
                action=event.get("action", ""),
                risk_score=event.get("risk_score", ""),
            )
        )


def _handle_history_or_export(args: argparse.Namespace) -> int:
    logger = setup_logging()

    if args.export is not None and args.output is None:
        raise ValueError("--output is required when using --export")

    events = _load_history_events(args)

    if args.history:
        _print_history(events)

    if args.export is None:
        return 0

    if args.export == "json":
        export_events_to_json(events, args.output)
    else:
        export_events_to_csv(events, args.output)

    logger.info("Exported %s DNS events to %s", len(events), args.output)
    return 0


def _resolve_cli_config(args: argparse.Namespace) -> dict[str, object]:
    load_env_file()

    interface = args.interface if args.interface is not None else load_dns_interface()
    threshold = (
        args.threshold if args.threshold is not None else load_dns_entropy_threshold()
    )
    threshold_config = load_dns_risk_thresholds(
        overrides=_risk_threshold_overrides(args)
    )
    debug = args.debug if args.debug is not None else load_dns_debug()
    webhook_url = args.webhook if args.webhook is not None else load_discord_webhook_url()

    if interface is not None and not interface.strip():
        raise ValueError("interface cannot be empty")

    return {
        "interface": interface,
        "threshold": threshold,
        "threshold_config": threshold_config,
        "debug": debug,
        "webhook_url": webhook_url,
        "demo": args.demo,
    }


def _log_startup(config: dict[str, object]) -> None:
    logger = setup_logging(debug=bool(config["debug"]))
    interface = config["interface"] or "auto"
    webhook_enabled = config["webhook_url"] is not None

    logger.info("DNS-Sentry starting")
    logger.info(
        "configuration interface=%s threshold=%s debug=%s demo=%s "
        "discord_webhook_configured=%s risk_thresholds=%s",
        interface,
        config["threshold"],
        config["debug"],
        config["demo"],
        webhook_enabled,
        config["threshold_config"],
    )

    if config["demo"]:
        logger.info("Starting demo mode")
    else:
        logger.info("Starting DNS sniffer")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = setup_logging()

    try:
        if args.check_env:
            return 0 if check_environment() else 1

        if args.history or args.export is not None:
            return _handle_history_or_export(args)

        config = _resolve_cli_config(args)

        if args.gui:
            run_gui(threshold_config=config["threshold_config"])  # type: ignore[arg-type]
            return 0

        _log_startup(config)

        if config["demo"]:
            run_demo(
                threshold=config["threshold"],  # type: ignore[arg-type]
                webhook_url=config["webhook_url"],  # type: ignore[arg-type]
                threshold_config=config["threshold_config"],  # type: ignore[arg-type]
            )
        else:
            start_dns_sniffer(
                interface=config["interface"],  # type: ignore[arg-type]
                webhook_url=config["webhook_url"],  # type: ignore[arg-type]
                threshold=config["threshold"],  # type: ignore[arg-type]
                threshold_config=config["threshold_config"],  # type: ignore[arg-type]
                debug=config["debug"],  # type: ignore[arg-type]
            )
    except KeyboardInterrupt:
        logger.info("Stopped by user")
        return 130
    except (RuntimeError, OSError, ValueError) as error:
        logger.error("%s", error)
        return 1

    return 0

