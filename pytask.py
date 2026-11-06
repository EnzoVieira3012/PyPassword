"""Ponto de entrada para empacotamento (PyInstaller / zipapp).

Sem argumentos: menu interativo. Com subcomando: CLI (add/list/search/...).
"""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) > 1:
        from src.cli import main as cli_main

        cli_main()
    else:
        from src.main import main as app_main

        app_main()


if __name__ == "__main__":
    main()
