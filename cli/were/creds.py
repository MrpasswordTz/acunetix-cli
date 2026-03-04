#!/usr/bin/env python3
"""
AcuScan CLI — Built-in public server credentials.

This Acunetix instance is provided FREE by MrpasswordTz
so everyone can use this vulnerability scanner without
buying a license or setting up their own server.

Users can override these by running:  acuscanner --setup
"""

import base64 as _b64

# Encoded to avoid casual scraping — NOT encryption, just obfuscation.
_A = _b64.b64decode(b'aHR0cHM6Ly8xMDQuMjQ4LjE5MS45MDozNDQzL2FwaS92MQ==').decode()
_K = _b64.b64decode(
    b'MTk4NmFkOGMwYTViM2RmNGQ3MDI4ZDVmM2MwNmU5MzZjYjI4NDIxOWYzNjBhNGMyYWJjNzRlZDQ1NGMxNjdkZjA='
).decode()


def get_public_url():
    """Return the built-in public Acunetix server URL."""
    return _A


def get_public_key():
    """Return the built-in public API key."""
    return _K
