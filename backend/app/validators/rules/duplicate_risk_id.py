from typing import Any, cast

import pandas as pd

from app.validators.models import Finding
from app.validators.rules.base import ValidationRule
from app.validators.severity import Severity


def _normalized_risk_id(value: object) -> str | None:
    """Return a comparable Risk ID, or None when missing or blank.

    Null, empty, and whitespace-only values are owned by the missing-ID
    rule and must not participate in duplicate detection.
    """
    if value is None or bool(pd.isna(cast(Any, value))):
        return None
    text = str(value).strip()
    if text == "":
        return None
    return text


class DuplicateRiskIdRule(ValidationRule):
    name = "duplicate-risk-id"
    description = "Detect duplicate values in the Risk ID column."

    def validate(self, df: pd.DataFrame) -> list[Finding]:
        if "Risk ID" not in df.columns:
            return []

        normalized = df["Risk ID"].map(_normalized_risk_id)
        eligible = normalized.notna()
        duplicate_mask = normalized.duplicated(keep=False) & eligible

        findings: list[Finding] = []
        for index in df.index[duplicate_mask]:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    row=int(index) + 2,
                    column="Risk ID",
                    message=f"Duplicate Risk ID: {normalized.at[index]}",
                    recommendation="Ensure every risk has a unique Risk ID.",
                )
            )

        return findings
