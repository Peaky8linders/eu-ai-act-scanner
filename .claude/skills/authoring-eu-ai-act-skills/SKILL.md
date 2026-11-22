---
name: authoring-eu-ai-act-skills
description: Use when creating a new EU AI Act skill for this plugin, reviewing an existing one for quality, or auditing the skill harness for coverage gaps. The authoring template enforces regulation citations, role-aware audience tiering, and rationalization rebuttals so skills are trustworthy to law practitioners, compliance officers, and engineers alike — not just demo-friendly. Also use this skill when the user asks to "improve the skills", "add a skill for Art. X", "write a skill for FRIAs", "audit our coverage of Annex III", or "strengthen the harness".
user_invocable: true
---

# Authoring EU AI Act Skills

This is the meta-skill. It describes how every EU AI Act skill in this plugin must be structured so the harness stays useful for engineers AND credible to law practitioners. Bad skills in a regulatory domain aren't just unhelpful — they're liability. This skill exists to keep that from happening.

## When to invoke

- User wants to add a skill: "write a skill for Art. 27 FRIAs", "add GPAI classification"
- User wants to improve a skill: "this skill feels vague", "a lawyer would never accept this wording"
- User asks about coverage gaps: "what's missing", "do we cover Annex III"
- You are about to write or edit any file under `skills/` in this repo

If you are editing a skill without first reading this meta-skill, stop and read it. The rules below are what separates a plugin that regulators and counsel will actually endorse from a plugin that gets dismissed as "AI slop for the AI Act".

## Core principles

### 1. Cite or abstain

Every regulatory claim in a skill must be traceable to an article + paragraph, not to memory, folklore, or marketing copy. If you cannot cite the paragraph, say you cannot and point at the article number alone.

| Good | Bad |
|---|---|
| "Art. 9(2)(a) requires identification of known and foreseeable risks." | "The regulation says you need a risk register." |
| "Art. 27 applies to deployers of high-risk AI in domains listed in Annex III.5, .7, .8." | "FRIAs are required for most high-risk AI." |
| "Art. 51(2) sets the systemic-risk threshold at ≥10^25 FLOPs of training compute." | "Large models need extra scrutiny." |

Article numbers without paragraph qualifiers are fine when the whole article applies. **Do not invent paragraph numbers or quote text verbatim unless you are reading the Official Journal.** If memory is fuzzy, cite the article and let the user verify.

### 2. Role-aware audience tiering

Every skill must state, at the top, who it is for. The four roles that matter:

- **Engineer** — builds the code, needs concrete patterns
- **Compliance officer** — owns the QMS, needs process and artefacts
- **Legal counsel** — signs off on conformity, needs unambiguous language + citations
- **Deployer / product lead** — decides whether to use/ship the system, needs risk and obligation mapping

A skill can serve multiple roles, but the opening paragraph should say which. Mix-and-match wording ("this might apply to you") loses every audience simultaneously. Precise wording ("if you are a deployer in Annex III domain 5, Art. 27 requires…") reaches the right reader and filters out the rest.

### 3. No hedging that erodes precision

Hedging is sometimes necessary (the regulation has grey areas). Hedging to avoid commitment is not.

- **Good**: "The Commission has not yet published delegated acts under Art. 15(4); the harmonised standard eINN 42001-adjacent wording is the current reference."
- **Bad**: "Art. 15 kinda covers accuracy and stuff like robustness — you probably want tests."

Phrases to avoid: "usually", "often", "tends to", "might want to consider". Phrases to prefer: "applies when", "requires", "is exempt if", "does not apply to".

### 4. The rationalization table

Agents (and humans) will try to talk themselves out of hard obligations. Common mistakes become skill-level failures. Every skill covering a specific obligation must include a **Common Rationalizations** table with:

- A plausible excuse in the left column (something Claude or a developer might actually think)
- The rebuttal with citation in the right column

This pattern is what keeps the skill from being advice theatre. The rationalization table converts implicit knowledge into explicit guardrails. See `interpreting-findings.md` and `eu-ai-act-reference.md` for live examples.

### 5. Cross-references, not duplication

Skills must link to each other rather than re-explaining. If your skill about FRIAs needs to establish that the system is high-risk, don't repeat Art. 6; cross-reference to `eu-ai-act-article-6-classification.md`. This keeps each skill focused and makes regulation updates manageable — when Art. X changes, one skill changes, not seven.

## Skill anatomy (template)

```markdown
---
name: <lowercase-hyphenated-name>
description: <2-3 sentence "use when" description, starting with "Use when". Name specific trigger phrases. End with the roles this skill serves.>
user_invocable: true
---

# <Human Title>

<One paragraph: what the skill does, who it is for, and why it exists. Include the
article(s) covered.>

## When to invoke

<Bulleted list of concrete user phrases that should trigger this skill. Be generous —
undertriggering is a worse failure mode than overtriggering in a regulatory domain.>

## Applies to

<Clear statement of risk tiers, operator roles, use cases, or article scope that are
IN scope. Equally clear statement of what is OUT of scope, with pointers to the
right skill for the out-of-scope cases.>

## Regulation scope

<1-2 paragraphs explaining the obligation, with article+paragraph citations. No
invented text; the article number is the source of truth.>

## What to do

<Concrete, ordered steps. Each step should be something Claude can actually execute
(read a file, invoke a command, ask a question, produce output). Avoid vague
guidance like "consider the implications".>

## Decision tree / reference tables

<Where the skill is a classifier (is this prohibited? is this high-risk? do I need
an FRIA?), use a decision tree or table. Avoid prose-only classification — the user
will misread it.>

## Cross-references

<Which related skills does this point at? Which upstream/downstream skills should
be invoked next?>

## Common rationalizations

<Required for any skill covering a specific obligation. 3-6 rows minimum.>

| Excuse | Rebuttal |
|---|---|

## Source of truth

<One sentence naming the authoritative source: "EU Regulation 2024/1689, published
in the Official Journal 12 July 2024." No exceptions.>
```

## Review checklist (for editing an existing skill)

Run through these in order when you're reviewing a skill. If any item fails, fix before committing.

1. **Frontmatter**: does the description start with "Use when"? Does it name at least three trigger phrases? Does it state the audience?
2. **Citations**: every regulatory claim has an article number. Claims at the paragraph level cite the paragraph. No fabricated paragraphs.
3. **Scope clarity**: the "Applies to" section states in and out of scope, with pointers.
4. **Decisions over narratives**: classification logic is a tree or table, not a paragraph.
5. **Rationalizations**: if the skill covers a specific obligation, there is a Common Rationalizations table with 3+ rows.
6. **Cross-references**: other related skills are linked, not re-explained.
7. **Length**: under 500 lines. If longer, move detail to a `references/` subfile and link to it.
8. **Tone**: no marketing language ("comprehensive", "powerful", "cutting-edge"). No emojis unless the user asked. Concise, auditable, professional.
9. **Source of truth**: the last line cites the Official Journal.

## Coverage audit (for the harness)

Every time a skill is added or removed, audit coverage. A complete EU AI Act skill harness should address:

### Classification and scope
- Art. 5 prohibited practices
- Art. 6 + Annex III high-risk classification
- Art. 50 limited-risk transparency triggers
- Art. 51 GPAI + systemic-risk thresholds
- Operator role determination (provider, deployer, importer, distributor, authorised representative, product manufacturer)

### High-risk obligations (Art. 8–15, 17)
- Risk management system (Art. 9)
- Data and data governance (Art. 10)
- Technical documentation (Art. 11 + Annex IV)
- Record-keeping (Art. 12)
- Transparency to deployers (Art. 13)
- Human oversight (Art. 14)
- Accuracy, robustness, cybersecurity (Art. 15)
- Quality management system (Art. 17)

### Deployer obligations (Art. 26, 27)
- Deployer duties
- Fundamental Rights Impact Assessment (FRIA)

### Post-market and lifecycle
- Conformity assessment (Art. 43, 47, 48)
- EU database registration (Art. 49)
- Post-market monitoring (Art. 72)
- Serious incident reporting (Art. 73)

### GPAI (Art. 53–55)
- GPAI provider obligations (Art. 53)
- GPAI systemic risk obligations (Art. 55)
- GPAI Code of Practice (Art. 56)

### Governance and enforcement
- Penalties (Art. 99)
- Timeline / application dates (Art. 113)

### Cross-cutting
- How to use the scanner itself
- How to interpret findings
- How to author new skills (this skill)

When a gap is identified, write the skill using the template above. Do not approximate — if you don't know the obligation in detail, the skill is worse than no skill at all.

## Style guide for law practitioners

Law practitioners read skills differently than engineers. Optimise for:

1. **Citation density over explanation**: they already know what risk management is. They need to know that *this* obligation is in *that* article.
2. **Unambiguous triggers**: "This applies when…" beats "This is relevant to…". Legal counsel thinks in if/then.
3. **No speculative compliance advice**: never say "this probably satisfies Art. X". Say "Art. X requires A, B, C. Here is evidence of A and B. C is absent."
4. **Name the open questions**: the regulation has grey zones (e.g. the exact scope of Art. 6(3) exemption). Name them as open rather than pretending they're settled.
5. **No motivational copy**: "empower your team to achieve compliance" is repellent to counsel. Strip all such phrasing.

## What NOT to put in a skill

- Marketing or sales material for this plugin or its parent products
- Advice about whether to adopt AI at all (out of scope)
- Content from paid legal databases or books (IP risk)
- Risk-tier verdicts ("your system is high-risk") — always surface evidence and let a human decide
- Dates or thresholds that depend on delegated acts not yet published
- Any wording that could be construed as legal advice to a specific client

## Source of truth

EU Regulation 2024/1689 ("AI Act"), published in the Official Journal of the European Union, 12 July 2024. All citations are to the consolidated text of that regulation. Where delegated acts, implementing acts, or harmonised standards are relevant, name them explicitly and state their current status.
