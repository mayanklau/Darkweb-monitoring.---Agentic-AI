from .agents import run_investigation
from .models import InvestigationRequest, MonitorRecord


def evaluate_monitor(monitor: MonitorRecord) -> dict:
    report = run_investigation(
        InvestigationRequest(
            title=f"Monitor evaluation - {monitor.name}",
            seed_text=monitor.query,
            generate_yara=True,
            run_swarm_simulation=True,
        )
    )
    triggered = report.risk_score >= monitor.threshold
    return {
        "triggered": triggered,
        "risk_score": report.risk_score,
        "threshold": monitor.threshold,
        "summary": report.executive_summary,
        "indicator_count": len(report.indicators),
    }

