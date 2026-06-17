"""ReportGenerator — incident report orchestration and Jinja2 rendering.

Used by the benchmark harness (argus benchmark run/render).
The daily/weekly/monthly report pipeline has been retired in favour of
the case-based workflow (argus case analyze / argus case report).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from argus.agents.report_agent import ReportAgent
from argus.agents.triage_agent import TriageAgent
from argus.config.settings import get_settings
from argus.models.report import CTIReport, ReportClassification, ReportType
from argus.storage.database import get_session
from argus.storage.models_db import ReportRecord

log = structlog.get_logger()

_TEMPLATE_DIR = Path(__file__).parent / "templates"
ProgressCallback = Callable[[str], None]


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


class ReportGenerator:
    def __init__(self, progress: ProgressCallback | None = None) -> None:
        self.jinja = _get_jinja_env()
        self.progress = progress

    def _progress(self, message: str) -> None:
        if self.progress is not None:
            self.progress(message)

    async def generate_incident_from_alerts(
        self,
        alerts: list[dict[str, Any]],
        context: str = "",
        title: str = "Incident Response Report",
        classification: str | ReportClassification = ReportClassification.AMBER,
        save: bool = True,
    ) -> CTIReport:
        """Triage alert tickets and generate an incident report from the findings."""
        if isinstance(classification, str):
            classification = ReportClassification(classification.upper())
        now = datetime.now(tz=UTC)
        self._progress("report: triaging incident alerts")
        alert_summary = await TriageAgent(progress=self.progress).run(
            alerts=alerts,
            context=context,
        )
        timestamps = [
            item.alert.timestamp for item in alert_summary.triaged_alerts if item.alert.timestamp
        ]
        report = CTIReport(
            report_type=ReportType.INCIDENT,
            title=title,
            generated_at=now,
            period_start=min(timestamps, default=now),
            period_end=max(timestamps, default=now),
            scope=context,
            classification=classification,
            alert_summary=alert_summary,
        )
        self._progress("report: writing incident narrative")
        report = await ReportAgent(progress=self.progress).run(report=report, scope=context)
        self._progress("report: rendering final markdown")
        report.content = self.render(report)
        if save:
            self._save(report)
        return report

    def render(self, report: CTIReport) -> str:
        template_name = f"{report.report_type.value}.md.j2"
        try:
            template = self.jinja.get_template(template_name)
            return template.render(report=report)
        except Exception as e:
            log.warning("report.render_failed", error=str(e), template=template_name)
            return self._render_fallback(report)

    def _render_fallback(self, report: CTIReport) -> str:
        lines = [
            f"# {report.title}",
            f"*Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}*",
            "",
            "## Executive Summary",
            report.executive_summary,
            "",
            "## Key Findings",
            *[f"- {f}" for f in report.key_findings],
            "",
            "## Threat Landscape",
            report.threat_landscape,
            "",
            "## Recommendations",
            *[
                f"**{r.priority.upper()}**: {r.action} — {r.rationale}"
                for r in report.recommendations
            ],
        ]
        return "\n".join(lines)

    def _save(self, report: CTIReport) -> None:
        settings = get_settings()
        settings.reports_dir.mkdir(parents=True, exist_ok=True)

        filename = (
            f"{report.report_type.value}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.md"
        )
        output_path = settings.reports_dir / filename
        output_path.write_text(report.content, encoding="utf-8")
        log.info("report.saved", path=str(output_path))

        try:
            with get_session() as session:
                session.add(ReportRecord(
                    report_type=report.report_type.value,
                    title=report.title,
                    content=report.content,
                    metadata_json=json.dumps(
                        {"scope": report.scope, "classification": report.classification.value},
                        default=str,
                    ),
                ))
        except Exception as e:
            log.warning("report.db_save_failed", error=str(e))
