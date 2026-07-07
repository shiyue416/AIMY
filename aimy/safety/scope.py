"""Scope checker — validates URLs against scope file."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


class ScopeChecker:
    """Validates whether a URL is within the defined test scope."""

    def __init__(self, scope_file: str = ""):
        self.scope_file = scope_file
        self._domains: set[str] = set()
        self._wildcards: list[str] = []
        self._loaded = False

    def load(self) -> None:
        """Load scope from file. Format: one domain/wildcard per line."""
        if self._loaded or not self.scope_file:
            return
        try:
            with open(self.scope_file, "r") as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("*."):
                        self._wildcards.append(line[2:])
                    else:
                        self._domains.add(line)
            self._loaded = True
        except FileNotFoundError:
            pass

    def is_in_scope(self, url_or_domain: str) -> bool:
        """Check if a URL or domain is in scope."""
        self.load()

        if not self._domains and not self._wildcards:
            return True  # no scope defined = everything allowed

        # Extract domain
        domain = url_or_domain.lower()
        if "://" in domain:
            try:
                domain = urlparse(domain).hostname or domain
            except Exception:
                pass

        # Exact match
        if domain in self._domains:
            return True

        # Wildcard match
        for wc in self._wildcards:
            if domain.endswith("." + wc) or domain == wc:
                return True

        return False

    def add_domain(self, domain: str) -> None:
        self._domains.add(domain.lower())
