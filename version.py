#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def app_version() -> str:
    path = Path(__file__).resolve().parent / "VERSION"
    try:
        return path.read_text(errors="replace").strip() or "0.0.0"
    except Exception:
        return "0.0.0"
