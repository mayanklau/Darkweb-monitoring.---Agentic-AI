from darkweb_monitoring.agents import extract_indicators, run_investigation
from darkweb_monitoring.models import InvestigationFocus, InvestigationRequest


def test_extract_indicators_finds_shell_tradecraft():
    indicators = extract_indicators(
        "Telegram @seller offers B374K and WSO PHP shells for example.edu with base64 and cron."
    )
    values = {indicator.value for indicator in indicators}
    assert "@seller" in values
    assert "example.edu" in values
    assert "B374K web shell family" in values
    assert "WSO web shell family" in values


def test_run_investigation_generates_yara_and_pivots():
    report = run_investigation(
        InvestigationRequest(
            title="Shell Sales",
            focus=InvestigationFocus.technical,
            seed_text=(
                "Telegram @seller offers B374K and WSO PHP shells, cPanel, SMTP, "
                ".gov targets, base64 obfuscation, .htaccess, and cron persistence."
            ),
        )
    )
    assert report.risk_score >= 70
    assert len(report.yara_rules) == 2
    assert any("payload" in pivot.lower() for pivot in report.pivots)
    assert any(finding.agent == "DetectionEngineer" for finding in report.findings)

