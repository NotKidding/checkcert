"""Output renderers.

Import render_rich for terminal output or render_json for machine-readable output.
Adding a new renderer (e.g. Markdown, CSV) means adding a module here and
exporting it — no changes needed elsewhere.
"""

from .json_out import render as render_json
from .rich_ui import render as render_rich

__all__ = ["render_rich", "render_json"]
