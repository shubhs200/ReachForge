"""
LLM adapters bundled with reachforge4.

Currently provides:
- openai.run_openai_json: Minimal JSON-only chat wrapper used by RF4 prompts.

This package makes reachforge4 self-contained for CI pipelines without requiring
the legacy reachforge.llm_openai module.
"""

from .openai import run_openai_json  # re-export for convenience

__all__ = ["run_openai_json"]
