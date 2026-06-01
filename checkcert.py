#!/usr/bin/env python3
# MIT License — see LICENSE
"""Entry-point shim. All logic lives in the checkcert/ package."""

import sys

from checkcert.cli import main

sys.exit(main())
