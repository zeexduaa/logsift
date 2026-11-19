"""Grouping messages that are "the same thing happening again".

"Timeout after 3012ms talking to 10.0.4.17:5432" and "Timeout after 2988ms talking to 10.0.4.9:5432" are one problem.
Masking the parts that vary (numbers, addresses, ids) gives both the template "Timeout after <num>ms talking to <ip>",
so a thousand errors collapse into the handful of things actually going wrong.
"""

from __future__ import annotations

import re

MAX_TEMPLATE = 240

# Order matters: the most specific shapes are replaced first, so a UUID isn't seen as a run of numbers.
MASKS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<time>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    (re.compile(r"\bhttps?://[^\s\"'<>]+"), "<url>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"), "<ip>"),
    # hex ids (request ids, hashes): at least 8 characters with both letters and digits, so words like "deadline" survive
    (re.compile(r"\b(?:0x)?(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,}\b"), "<hex>"),
    (re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?=[a-zA-Z%]{0,3}\b)"), "<num>"),
    (re.compile(r"'[^'\n]{1,200}'"), "'<str>'"),
    (re.compile(r'"[^"\n]{1,200}"'), '"<str>"'),
]


def template(message: str) -> str:
    """The shape of a message with its changing parts masked. Only the first line counts: a stack trace below an error
    doesn't make it a different error."""
    text = message.split("\n", 1)[0].strip()[:1000]
    for pattern, mask in MASKS:
        text = pattern.sub(mask, text)
    text = re.sub(r"(<num>)(?:,\s*<num>)+", r"\1", text)  # "1, 2, 3, 4" is one list of numbers
    text = re.sub(r"\s+", " ", text)
    return text[:MAX_TEMPLATE] or "(empty)"
