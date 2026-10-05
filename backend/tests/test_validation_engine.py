import pandas as pd

from app.validators.engine import ValidationEngine


def test_duplicate_risk_ids_create_findings(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = pd.concat(
    [valid_risk_dataframe, valid_risk_dataframe],
    ignore_index=True,
)

    dataframe.loc[1, "Title"] = "Missing MFA"
    dataframe.loc[1, "Description"] = "MFA is not enabled."

    result = ValidationEngine().validate(dataframe)

    assert result.score == 80
    assert result.audit_readiness == "Needs Improvement"
    assert len(result.findings) == 2
    assert all(finding.severity == "High" for finding in result.findings)
    assert all(finding.column == "Risk ID" for finding in result.findings)


def test_unique_risk_ids_create_no_findings(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    result = ValidationEngine().validate(valid_risk_dataframe)

    assert result.score == 100
    assert result.audit_readiness == "Ready"
    assert result.findings == []


def test_missing_owner_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Owner"] = ""

    result = ValidationEngine().validate(dataframe)

    assert result.score == 90
    assert result.audit_readiness == "Ready"
    assert len(result.findings) == 1
    assert result.findings[0].column == "Owner"
    assert result.findings[0].message == "Risk has no assigned owner."


def test_missing_owner_whitespace_null_and_populated_values(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    row1 = valid_risk_dataframe.copy()
    row2 = valid_risk_dataframe.copy()
    row3 = valid_risk_dataframe.copy()
    row4 = valid_risk_dataframe.copy()
    row5 = valid_risk_dataframe.copy()

    row1.loc[0, "Owner"] = "   "
    row2.loc[0, "Owner"] = "\t\t"
    row3.loc[0, "Owner"] = None
    row4.loc[0, "Owner"] = ""
    row5.loc[0, "Owner"] = "Alice Security"

    row1.loc[0, "Risk ID"] = "R-1"
    row2.loc[0, "Risk ID"] = "R-2"
    row3.loc[0, "Risk ID"] = "R-3"
    row4.loc[0, "Risk ID"] = "R-4"
    row5.loc[0, "Risk ID"] = "R-5"

    dataframe = pd.concat([row1, row2, row3, row4, row5], ignore_index=True)

    result = ValidationEngine().validate(dataframe)
    owner_findings = [
        finding for finding in result.findings if finding.column == "Owner"
    ]

    assert len(owner_findings) == 4
    assert [finding.row for finding in owner_findings] == [2, 3, 4, 5]
    assert all(finding.column == "Owner" for finding in owner_findings)
    assert all(
        finding.message == "Risk has no assigned owner."
        for finding in owner_findings
    )
    assert not any(finding.row == 6 for finding in owner_findings)



def test_invalid_likelihood_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Likelihood"] = 9

    result = ValidationEngine().validate(dataframe)

    assert result.score == 90
    assert result.audit_readiness == "Ready"
    assert len(result.findings) == 1
    assert result.findings[0].column == "Likelihood"
    assert result.findings[0].message == "Invalid likelihood value: 9"


def test_invalid_impact_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Impact"] = 8

    result = ValidationEngine().validate(dataframe)

    assert result.score == 90
    assert result.audit_readiness == "Ready"
    assert len(result.findings) == 1
    assert result.findings[0].column == "Impact"
    assert result.findings[0].message == "Invalid impact value: 8"


def test_missing_title_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Title"] = ""

    result = ValidationEngine().validate(dataframe)

    assert result.score == 90
    assert result.audit_readiness == "Ready"
    assert len(result.findings) == 1
    assert result.findings[0].column == "Title"
    assert result.findings[0].message == "Risk has no title."


def test_empty_risk_id_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Risk ID"] = ""

    result = ValidationEngine().validate(dataframe)

    assert len(result.findings) == 1
    assert result.findings[0].column == "Risk ID"


def test_missing_description_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Description"] = ""

    result = ValidationEngine().validate(dataframe)

    assert len(result.findings) == 1
    assert result.findings[0].column == "Description"


def test_missing_treatment_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Treatment"] = ""

    result = ValidationEngine().validate(dataframe)

    assert len(result.findings) == 1
    assert result.findings[0].column == "Treatment"


def test_missing_review_date_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Review Date"] = ""

    result = ValidationEngine().validate(dataframe)

    assert len(result.findings) == 1
    assert result.findings[0].column == "Review Date"


def test_invalid_review_date_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Review Date"] = "not-a-date"

    result = ValidationEngine().validate(dataframe)

    assert any(
        finding.message == "Invalid review date."
        for finding in result.findings
    )


def test_past_due_review_date_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.copy()
    dataframe.loc[0, "Review Date"] = "2023-01-01"

    result = ValidationEngine().validate(dataframe)

    assert any(
        finding.message == "Review date has passed."
        for finding in result.findings
    )

def test_duplicate_rows_create_findings(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = pd.concat(
        [valid_risk_dataframe, valid_risk_dataframe],
        ignore_index=True,
    )

    result = ValidationEngine().validate(dataframe)

    duplicate_row_findings = [
        finding
        for finding in result.findings
        if finding.message == "Duplicate row detected."
    ]

    assert len(duplicate_row_findings) == 2


def test_empty_row_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    empty_row = pd.DataFrame(
        [{column: None for column in valid_risk_dataframe.columns}]
    )
    dataframe = pd.concat(
        [valid_risk_dataframe, empty_row],
        ignore_index=True,
    )

    result = ValidationEngine().validate(dataframe)

    assert any(
        finding.message == "Empty row detected."
        for finding in result.findings
    )


def test_missing_required_column_creates_finding(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    dataframe = valid_risk_dataframe.drop(columns=["Owner"])

    result = ValidationEngine().validate(dataframe)

    assert any(
        finding.message == "Missing required column: Owner"
        for finding in result.findings
    )


def test_blank_risk_ids_are_not_reported_as_duplicates(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    first = valid_risk_dataframe.copy()
    second = valid_risk_dataframe.copy()
    third = valid_risk_dataframe.copy()
    first.loc[0, "Risk ID"] = None
    second.loc[0, "Risk ID"] = ""
    third.loc[0, "Risk ID"] = "   "
    second.loc[0, "Title"] = "Missing MFA"
    third.loc[0, "Title"] = "Unpatched server"
    dataframe = pd.concat([first, second, third], ignore_index=True)

    result = ValidationEngine().validate(dataframe)
    duplicate_findings = [
        finding
        for finding in result.findings
        if finding.message.startswith("Duplicate Risk ID")
    ]
    missing_findings = [
        finding
        for finding in result.findings
        if finding.message == "Risk ID is missing."
    ]

    assert duplicate_findings == []
    assert [finding.row for finding in missing_findings] == [2, 3, 4]


def test_populated_duplicate_risk_ids_keep_spreadsheet_rows(
    valid_risk_dataframe: pd.DataFrame,
) -> None:
    first = valid_risk_dataframe.copy()
    second = valid_risk_dataframe.copy()
    third = valid_risk_dataframe.copy()
    first.loc[0, "Risk ID"] = "R-100"
    second.loc[0, "Risk ID"] = "  R-100  "
    third.loc[0, "Risk ID"] = None
    second.loc[0, "Title"] = "Missing MFA"
    third.loc[0, "Title"] = "Unpatched server"
    dataframe = pd.concat([first, second, third], ignore_index=True)

    result = ValidationEngine().validate(dataframe)
    duplicate_findings = [
        finding
        for finding in result.findings
        if finding.message.startswith("Duplicate Risk ID")
    ]

    assert [finding.row for finding in duplicate_findings] == [2, 3]
    assert all(
        finding.message == "Duplicate Risk ID: R-100"
        for finding in duplicate_findings
    )
    assert all(finding.column == "Risk ID" for finding in duplicate_findings)
    assert not any(finding.row == 4 for finding in duplicate_findings)
