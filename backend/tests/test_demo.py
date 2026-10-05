from datetime import date
from io import StringIO

import pandas as pd
from fastapi.testclient import TestClient

from app.demo.samples import risk_register_csv
from app.main import app
from app.validators.engine import ValidationEngine
from app.validators.rules.required_columns import RequiredColumnsRule

client = TestClient(app)


def test_demo_is_served_without_changing_health_or_upload_api() -> None:
    response = client.get("/demo")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Risk register" in response.text
    assert client.get("/demo-assets/app.js").status_code == 200
    assert client.get("/demo-assets/styles.css").status_code == 200
    assert client.get("/").json()["status"] == "healthy"
    assert client.get("/health").json() == {"status": "healthy"}


def test_upload_guide_lists_every_required_column_and_format() -> None:
    page = client.get("/demo").text
    assert '<details class="format-guide">' in page
    for column in RequiredColumnsRule.REQUIRED_COLUMNS:
        assert f"<li><code>{column}</code></li>" in page
    assert "1 to 5" in page
    assert "YYYY-MM-DD" in page
    assert 'href="/demo/samples/corrected.csv"' in page


def test_samples_show_actionable_defects_then_a_clean_register() -> None:
    messy = client.get("/demo/samples/messy.csv")
    assert messy.status_code == 200
    assert "attachment" in messy.headers["content-disposition"]
    assert messy.headers["cache-control"] == "no-store"
    result = client.post(
        "/upload/risk-register",
        files={"file": ("messy.csv", messy.content, "text/csv")},
    )
    assert result.status_code == 200
    data = result.json()
    assert data["rows"] == 3
    assert data["score"] == 40
    assert len(data["findings"]) == 6
    assert {f["column"] for f in data["findings"]} == {
        "Risk ID", "Owner", "Review Date", "Treatment", "Likelihood",
    }
    assert all(f["recommendation"] for f in data["findings"])

    corrected = client.get("/demo/samples/corrected.csv")
    result = client.post(
        "/upload/risk-register",
        files={"file": ("corrected.csv", corrected.content, "text/csv")},
    )
    assert result.status_code == 200
    assert result.json()["findings"] == []
    assert result.json()["score"] == 100


def test_sample_dates_are_relative_instead_of_expiring_next_year() -> None:
    future_today = date(2040, 12, 1)
    messy = pd.read_csv(StringIO(risk_register_csv("messy", future_today)))
    corrected = pd.read_csv(StringIO(risk_register_csv("corrected", future_today)))
    assert date.fromisoformat(messy.loc[0, "Review Date"]) < future_today
    assert all(date.fromisoformat(d) > future_today for d in corrected["Review Date"])
    assert ValidationEngine().validate(corrected).findings == []


def test_unknown_samples_and_path_traversal_are_not_served() -> None:
    assert client.get("/demo/samples/real-data.csv").status_code == 404
    assert client.get("/demo-assets/%2e%2e/main.py").status_code == 404
    assert client.get("/demo/samples/%2e%2e%2fmain.py").status_code == 404
