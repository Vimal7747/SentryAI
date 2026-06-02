"""Minimal .env loader (stdlib only).

Loads KEY=VALUE pairs from a .env file into os.environ WITHOUT overwriting
variables already set in the real environment (env always wins over .env).
Used so `--live` can pick up API keys from a local, gitignored .env during
development. Never commit a .env containing real secrets.
"""

from __future__ import annotations

import os
from typing import Optional


def load_dotenv(path: Optional[str] = None) -> bool:
    """Load .env into os.environ (setdefault). Returns True if a file was read.

    Search order when *path* is None: ./.env then the project root (one level
    above this package).
    """
    candidates = []
    if path:
        candidates.append(path)
    else:
        candidates.append(os.path.join(os.getcwd(), ".env"))
        candidates.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

    for p in candidates:
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, val)
        return True
    return False
