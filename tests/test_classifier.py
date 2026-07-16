"""Tests for the deterministic PromptClassifier."""

from __future__ import annotations

from promptshield.classifier import (
    ConfigFileStrategy,
    DatabaseDumpStrategy,
    EmailConversationStrategy,
    GenericDocumentStrategy,
    LogOutputStrategy,
    PromptClassifier,
    SourceCodeStrategy,
)


def test_deterministic() -> None:
    clf = PromptClassifier()
    prompt = "def foo():\n    return 1\n# comment\n"
    a = clf.classify(prompt)
    b = clf.classify(prompt)
    assert a == b
    assert a[0].label == "source_code"


def test_no_exception() -> None:
    clf = PromptClassifier()
    samples = [
        "",
        "   ",
        "\x00\x01",
        "café 日本語 🚀",
        "x" * 50_000,
        "{'weird': True}",
        "\n" * 100,
    ]
    for sample in samples:
        labels = clf.classify(sample)
        assert isinstance(labels, list)
        assert labels
        assert labels[0].confidence >= 0.0


def test_each_strategy() -> None:
    """At least one positive case per strategy (via full classifier or unit)."""
    # Source code
    code = "import os\ndef main():\n    x = 1\n    return x\n"
    assert SourceCodeStrategy().evaluate(code) is not None
    assert SourceCodeStrategy().evaluate(code).label == "source_code"

    # Config
    config = "API_KEY=secret\nDEBUG=true\n[database]\nhost=localhost\n"
    assert ConfigFileStrategy().evaluate(config) is not None

    # Log
    log = (
        "2024-01-15 10:00:01 INFO Starting service\n"
        "2024-01-15 10:00:02 ERROR Connection failed\n"
        "Traceback (most recent call last):\n"
        '  File "app.py", line 1, in <module>\n'
    )
    assert LogOutputStrategy().evaluate(log) is not None

    # Database dump
    dump = (
        "INSERT INTO users VALUES (1, 'a');\n"
        "INSERT INTO users VALUES (2, 'b');\n"
        "id|name|email\n"
        "1|alice|a@b.co\n"
    )
    assert DatabaseDumpStrategy().evaluate(dump) is not None

    # Email
    email = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Hello\n"
        "\n"
        "> quoted previous message\n"
        "> still quoted\n"
    )
    assert EmailConversationStrategy().evaluate(email) is not None

    # Generic document (prose)
    doc = (
        "This is a complete sentence about the weather. "
        "Another sentence follows with a clear point of view for the reader.\n\n"
        "A second paragraph continues the discussion for the audience."
    )
    label = GenericDocumentStrategy().evaluate(doc)
    assert label is not None
    assert label.label == "generic_document"

    # Full classifier finds technical labels
    clf = PromptClassifier()
    assert clf.classify(code)[0].label == "source_code"
    assert clf.classify(config)[0].label == "config_file"
    assert clf.classify(log)[0].label == "log_output"


def test_unknown() -> None:
    clf = PromptClassifier()
    # Short gibberish without code/config/log patterns
    labels = clf.classify("xyzzy plugh 12345")
    assert len(labels) == 1
    assert labels[0].label == "unknown"
    assert labels[0].confidence == 1.0
    assert "No recognized pattern" in labels[0].evidence[0]


def test_confidence_saturated() -> None:
    """Rich code sample should not exceed confidence 1.0."""
    rich = """
import sys
# comment
def foo():
    class Bar:
        def method(self):
            return 1
/* block */
public static void main() {
    const x = 1;
    let y = 2;
    var z = 3;
}
"""
    label = SourceCodeStrategy().evaluate(rich)
    assert label is not None
    assert 0.0 < label.confidence <= 1.0
