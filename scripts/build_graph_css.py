"""Regenerate ``scanner/data/graph.css`` — the utility CSS inlined into the graph page.

The context graph HTML is a single standalone file that must open with **no
network access**, so it cannot load Tailwind from a CDN the way it used to.
Instead the utilities used by the page template are compiled once, here, and
inlined as a ``<style>`` block.

The input is the *template itself*: a page generated from a fixed synthetic
scan, with the ``<style>`` block emptied so previously compiled CSS cannot feed
back into the candidate set. Class names written by the page's JavaScript are
scanned too, because Tailwind's extractor reads the whole document.

Usage (requires Node; nothing else is added to the project's dependencies)::

    python scripts/build_graph_css.py

Review the diff of ``scanner/data/graph.css``: a new utility class in the
template should show up as a new rule, and nothing else should move.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Pinned so the vendored artifact is reproducible: a version bump is a
# deliberate, reviewable change.
TAILWIND_VERSION = "3.4.17"

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "scanner" / "data" / "graph.css"

INPUT_CSS = "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n"
CONFIG_JS = """module.exports = {{
  content: ["./graph_template.html"],
  theme: {{ extend: {{}} }},
}};
"""


def _template_html() -> str:
    """Render the graph page from a fixed synthetic scan, minus its CSS."""
    sys.path.insert(0, str(ROOT))
    from scanner.models import ScanResult
    from scanner.visual_graph import generate_visual_graph

    scan = ScanResult(
        project_name="build-graph-css",
        is_ai_system=True,
        overall_compliance_pct=50.0,
        compliance_scores={"human_oversight": 10.0, "security": 70.0},
    )
    page = generate_visual_graph(scan)
    # Drop the previous compiled CSS (and the page's own rules) so the scan sees
    # only the markup + JavaScript that consumes utilities.
    return re.sub(r"<style>.*?</style>", "<style></style>", page, flags=re.DOTALL)


def main() -> int:
    npx = shutil.which("npx")
    if not npx:
        print("npx not found: install Node.js to regenerate the vendored CSS.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="graph-css-") as tmp:
        work = Path(tmp)
        (work / "graph_template.html").write_text(_template_html(), encoding="utf-8")
        (work / "input.css").write_text(INPUT_CSS, encoding="utf-8")
        (work / "tailwind.config.js").write_text(CONFIG_JS.format(), encoding="utf-8")

        result = subprocess.run(
            [
                npx,
                "--yes",
                f"tailwindcss@{TAILWIND_VERSION}",
                "-c",
                "tailwind.config.js",
                "-i",
                "input.css",
                "-o",
                "graph.css",
                "--minify",
            ],
            cwd=work,
            check=False,
        )
        if result.returncode != 0:
            print("tailwindcss failed; see output above.", file=sys.stderr)
            return result.returncode

        css = (work / "graph.css").read_text(encoding="utf-8")
        if "https://" in css.replace("https://tailwindcss.com", ""):
            print("compiled CSS contains a remote URL; refusing to vendor it.", file=sys.stderr)
            return 1

    OUTPUT.write_text(css, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(css):,} bytes, tailwindcss {TAILWIND_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
