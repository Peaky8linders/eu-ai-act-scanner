"""Curated verbatim repairs for ``official_eu_ai_act.OFFICIAL_ARTICLE_TEXT``.

``official_eu_ai_act.py`` is generated from the EUR-Lex Cellar text of
Regulation (EU) 2024/1689 (CELEX 32024R1689). The fetch occasionally drops
structural markers that the Official Journal carries — most notably leading
paragraph numbers and the closing "binding in its entirety" clause. Editing
the generated module by hand is fragile because a refresh overwrites it, so
confirmed-correct verbatim repairs live here and are merged on top at read time.

Each entry is the complete, verbatim EUR-Lex text for the keyed provision
(title prefix included, matching the generated module's shape) — never a
paraphrase.

Article 113 repair
------------------
The generated ``OFFICIAL_ARTICLE_TEXT["Article 113"]`` rendered the three
subparagraphs without their ``1./2./3.`` paragraph numbers and omitted the
closing "binding in its entirety" sentence. The regulation itself
cross-references ``Article 113(3), point (a)`` (in Articles 111(2) and 112),
confirming that paragraph 3 carries points ``(a)(b)(c)``. This repair restores
the paragraph numbering and appends the closing clause; the substantive
``(a)(b)(c)`` text is byte-identical to the generated value.

Source: Regulation (EU) 2024/1689, Article 113 (CELEX 32024R1689),
Official Journal L series, 12 July 2024.
"""

from __future__ import annotations

from scanner.data.official_eu_ai_act import OFFICIAL_ARTICLE_TEXT

OFFICIAL_TEXT_PATCHES: dict[str, str] = {
    "Article 113": (
        "Entry into force and application "
        "1. This Regulation shall enter into force on the twentieth day "
        "following that of its publication in the Official Journal of the "
        "European Union. "
        "2. It shall apply from 2 August 2026. "
        "3. However: "
        "(a) Chapters I and II shall apply from 2 February 2025; "
        "(b) Chapter III Section 4, Chapter V, Chapter VII and Chapter XII "
        "and Article 78 shall apply from 2 August 2025, with the exception "
        "of Article 101; "
        "(c) Article 6(1) and the corresponding obligations in this "
        "Regulation shall apply from 2 August 2027. "
        "This Regulation shall be binding in its entirety and directly "
        "applicable in all Member States."
    ),
}


def get_official_article_text(key: str) -> str:
    """Return verbatim EUR-Lex text for ``key`` with curated patches merged on top.

    Accepts official corpus keys (``"Article 113"``, ``"Annex III"``) as well as
    internal shorthand (``"Art. 113"``). Returns ``""`` when unknown.
    """
    raw = (key or "").strip()
    if not raw:
        return ""
    if raw.startswith("Art. "):
        raw = "Article " + raw[len("Art. ") :].strip()
    if raw in OFFICIAL_TEXT_PATCHES:
        return OFFICIAL_TEXT_PATCHES[raw]
    return OFFICIAL_ARTICLE_TEXT.get(raw, "")


__all__ = [
    "OFFICIAL_TEXT_PATCHES",
    "get_official_article_text",
]
