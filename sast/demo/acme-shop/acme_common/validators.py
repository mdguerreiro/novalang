"""Input validators shared by Acme services."""
import re

SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def is_safe_slug(value):
    return SLUG_RE.fullmatch(value) is not None


def is_valid_email(value):
    return "@" in value and len(value) < 254
