# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Main CLI entry point for ActChain.
"""

import sys
import time
from rich.align import Align
from rich.console import Console
from rich.markup import escape as rich_escape

from .commands import cli
from ..logging_config import configure_logging
from ..utils.system_utils import SystemUtils

console = Console()


def display_logo():
    """Display ActChain ASCII art logo."""
    console.clear()

    logo = r"""
    █████╗  ██████╗████████╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
   ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║
   ███████║██║        ██║   ██║     ███████║███████║██║██╔██╗ ██║
   ██╔══██║██║        ██║   ██║     ██╔══██║██╔══██║██║██║╚██╗██║
   ██║  ██║╚██████╗   ██║   ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
   ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
    """

    console.print(Align.center(logo, style="bold cyan"))
    time.sleep(1.0)
    console.clear()


def main():
    """Main entry point for ActChain CLI."""
    try:
        # Display the logo only for interactive terminal sessions, and not
        # for --help/--version: clearing the screen and sleeping would break
        # CI usage and piped output.
        informational = any(arg in ('--help', '-h', '--version') for arg in sys.argv[1:])
        if sys.stdout.isatty() and not informational:
            display_logo()

        # Check dependencies
        if not SystemUtils.check_dependencies():
            console.print(
                "[bold red]Error:[/bold red] Missing dependencies. "
                "Please ensure all required dependencies are installed."
            )
            sys.exit(1)

        # Configure default logging
        configure_logging(verbose=False)

        # Run CLI
        cli()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {rich_escape(str(e))}")
        sys.exit(1)


if __name__ == '__main__':
    main()
