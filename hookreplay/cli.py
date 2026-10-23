"""The seed CLI deliberately exposes only record and replay."""

from __future__ import annotations

import argparse
import math
import sys

from . import __version__, record, replay, store


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, f"hookreplay: {message}\n")


def positive_seconds(value):
    try:
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            raise ValueError
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError("expected finite positive seconds") from None
    return number


def positive_integer(value):
    try:
        number = int(value)
        if number <= 0:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    return number


def port_number(value):
    try:
        number = int(value)
        if not 0 <= number <= 65535:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("expected an integer port in 0..65535") from None
    return number


def parser():
    root = Parser(prog="hookreplay", description="Record and replay local GitHub webhook bytes")
    root.add_argument("--version", action="version", version=f"hookreplay {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    recorder = commands.add_parser("record", help="record local POST deliveries")
    recorder.add_argument("--dir", required=True, dest="path")
    recorder.add_argument("--host", default="127.0.0.1")
    recorder.add_argument("--port", type=port_number, default=0)
    recorder.add_argument("--max-body-bytes", type=positive_integer, default=2097152)
    recorder.add_argument("--read-timeout", type=positive_seconds, default=10.0)
    sender = commands.add_parser("replay", help="replay one record without signing")
    sender.add_argument("file")
    sender.add_argument("--url", required=True)
    sender.add_argument("--timeout", type=positive_seconds, default=10.0)
    sender.add_argument("--format", choices=("text", "json"), default="text")
    return root


def main(argv=None) -> int:
    options = vars(parser().parse_args(argv))
    command = options.pop("command")
    try:
        return record.run(**options) if command == "record" else replay.run(**options)
    except store.RecordError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"{command}: {type(exc).__name__}", file=sys.stderr)
        return 2
