"""Command-line entrypoint for DNS-Sentry."""

import argparse
from collections.abc import Sequence

from .config import (
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
    load_env_file,
)
from .demo import run_demo
from .logging_config import setup_logging
from .sniffer import start_dns_sniffer


def _non_negative_float(value: str) -> float:
    try:
        threshold = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a float") from error

    if threshold < 0:
        raise argparse.ArgumentTypeError("must be non-negative")

    return threshold


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
        "--debug",
        action="store_true",
        default=None,
        help="enable debug output",
    )
    parser.add_argument("--webhook", help="Discord webhook URL")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run simulated demo mode without network sniffing",
    )

    return parser


def _resolve_cli_config(args: argparse.Namespace) -> dict[str, str | float | bool | None]:
    load_env_file()

    interface = args.interface if args.interface is not None else load_dns_interface()
    threshold = (
        args.threshold if args.threshold is not None else load_dns_entropy_threshold()
    )
    debug = args.debug if args.debug is not None else load_dns_debug()
    webhook_url = args.webhook if args.webhook is not None else load_discord_webhook_url()

    if interface is not None and not interface.strip():
        raise ValueError("interface cannot be empty")

    return {
        "interface": interface,
        "threshold": threshold,
        "debug": debug,
        "webhook_url": webhook_url,
        "demo": args.demo,
    }


def _log_startup(config: dict[str, str | float | bool | None]) -> None:
    logger = setup_logging(debug=bool(config["debug"]))
    interface = config["interface"] or "auto"
    webhook_enabled = config["webhook_url"] is not None

    logger.info("DNS-Sentry starting")
    logger.info(
        "configuration interface=%s threshold=%s debug=%s demo=%s "
        "discord_webhook_configured=%s",
        interface,
        config["threshold"],
        config["debug"],
        config["demo"],
        webhook_enabled,
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
        config = _resolve_cli_config(args)
        _log_startup(config)

        if config["demo"]:
            run_demo(
                threshold=config["threshold"],  # type: ignore[arg-type]
                webhook_url=config["webhook_url"],  # type: ignore[arg-type]
            )
        else:
            start_dns_sniffer(
                interface=config["interface"],  # type: ignore[arg-type]
                webhook_url=config["webhook_url"],  # type: ignore[arg-type]
                threshold=config["threshold"],  # type: ignore[arg-type]
                debug=config["debug"],  # type: ignore[arg-type]
            )
    except KeyboardInterrupt:
        logger.info("Stopped by user")
        return 130
    except (RuntimeError, OSError, ValueError) as error:
        logger.error("%s", error)
        return 1

    return 0

