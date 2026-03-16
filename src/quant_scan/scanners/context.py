"""Context analysis module — adjusts finding confidence based on context clues."""

from __future__ import annotations

import re

from quant_scan.core.models import Finding

# Patterns that indicate the line is a comment
_COMMENT_PREFIXES = re.compile(r"^\s*(#|//|/\*|\*)")

# Paths that suggest test / non-production code
_TEST_PATH_SEGMENTS = {"test", "tests", "spec", "specs", "mock", "mocks", "__test__", "__tests__", "_test", "_tests"}

# Suppression markers that signal intentional acceptance of risk
_SUPPRESSION_MARKERS = ("# noqa", "# nosec", "pragma: no cover")

# Tokens in nearby context that raise confidence (sensitive data nearby)
_SENSITIVE_TOKENS = {"password", "secret", "private_key", "credential", "credentials", "api_key", "apikey"}

# Tokens in nearby context that lower confidence (demo / test context)
_DEMO_TOKENS = {"test", "example", "sample", "demo", "mock"}


class ContextAnalyzer:
    """Post-process findings to refine confidence based on surrounding context.

    The analyzer applies a sequence of heuristic rules that increase or
    decrease the ``confidence`` field on each :class:`Finding`.  Findings
    whose confidence drops below 0.2 are filtered out entirely.
    """

    # Minimum confidence to keep a finding in the final results
    MIN_CONFIDENCE = 0.2

    def analyze(self, findings: list[Finding]) -> list[Finding]:
        """Adjust confidence of each finding and filter low-confidence ones.

        Parameters
        ----------
        findings:
            Raw findings produced by a scanner.

        Returns
        -------
        list[Finding]
            A new list with adjusted confidence values.  Findings whose
            confidence falls below :pyattr:`MIN_CONFIDENCE` are excluded.
        """
        adjusted: list[Finding] = []

        for finding in findings:
            confidence = finding.confidence

            # --- Rule (a): test / spec / mock path segments ----------------
            confidence = self._apply_test_path_rule(finding, confidence)

            # --- Rule (b): suppression markers in line content -------------
            confidence = self._apply_suppression_rule(finding, confidence)

            # --- Rule (c): line is a comment -------------------------------
            confidence = self._apply_comment_rule(finding, confidence)

            # --- Rule (d): sensitive tokens in nearby context --------------
            confidence = self._apply_sensitive_context_rule(finding, confidence)

            # --- Rule (e): demo / test tokens in nearby context ------------
            confidence = self._apply_demo_context_rule(finding, confidence)

            # Clamp to [0.0, 1.0]
            confidence = max(0.0, min(1.0, confidence))

            if confidence >= self.MIN_CONFIDENCE:
                updated = finding.model_copy(update={"confidence": confidence})
                adjusted.append(updated)

        return adjusted

    # ------------------------------------------------------------------
    # Private rule methods
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_test_path_rule(finding: Finding, confidence: float) -> float:
        """Reduce confidence if the file path contains test-related segments."""
        path_lower = finding.location.file_path.lower().replace("\\", "/")
        parts = set(path_lower.split("/"))
        # Also check for files like "test_foo.py" or "foo_test.py"
        filename = parts.pop() if parts else ""
        parts_to_check = parts | {filename}
        for segment in _TEST_PATH_SEGMENTS:
            if segment in parts_to_check or segment in filename:
                return confidence - 0.3
        return confidence

    @staticmethod
    def _apply_suppression_rule(finding: Finding, confidence: float) -> float:
        """Reduce confidence when the line contains a suppression marker."""
        line = finding.location.line_content.lower()
        for marker in _SUPPRESSION_MARKERS:
            if marker in line:
                return confidence - 0.5
        return confidence

    @staticmethod
    def _apply_comment_rule(finding: Finding, confidence: float) -> float:
        """Set confidence to 0.1 if the matched line is a comment."""
        if _COMMENT_PREFIXES.match(finding.location.line_content):
            return 0.1
        return confidence

    @staticmethod
    def _apply_sensitive_context_rule(finding: Finding, confidence: float) -> float:
        """Increase confidence when nearby lines mention sensitive data."""
        context_text = " ".join(finding.location.context_before + finding.location.context_after).lower()
        for token in _SENSITIVE_TOKENS:
            if token in context_text:
                return min(confidence + 0.2, 1.0)
        return confidence

    @staticmethod
    def _apply_demo_context_rule(finding: Finding, confidence: float) -> float:
        """Reduce confidence when nearby lines suggest demo/test usage."""
        context_text = " ".join(finding.location.context_before + finding.location.context_after).lower()
        for token in _DEMO_TOKENS:
            if token in context_text:
                return confidence - 0.2
        return confidence
