"""ReportGenerator — orchestrates intel collection and Jinja2 rendering."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from argus.agents.errors import AgentError
from argus.agents.ioc_agent import IOCEnrichmentAgent
from argus.agents.report_agent import ReportAgent
from argus.agents.threat_actor_agent import ThreatActorAgent
from argus.agents.triage_agent import TriageAgent
from argus.agents.vuln_agent import VulnIntelAgent
from argus.config.settings import get_settings
from argus.models.ioc import IOCEnrichmentResult
from argus.models.report import CTIReport, ReportClassification, ReportType
from argus.storage.database import get_session
from argus.storage.models_db import ReportRecord

log = structlog.get_logger()

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _get_period(report_type: ReportType, now: datetime) -> tuple[datetime, datetime]:
    end = now
    match report_type:
        case ReportType.DAILY:
            start = now - timedelta(days=1)
        case ReportType.WEEKLY:
            start = now - timedelta(weeks=1)
        case ReportType.MONTHLY:
            start = now - timedelta(days=30)
        case ReportType.YEARLY:
            start = now - timedelta(days=365)
        case ReportType.INCIDENT:
            start = now - timedelta(hours=72)
        case _:
            start = now - timedelta(days=1)
    return start, end


class ReportGenerator:
    def __init__(self) -> None:
        self.jinja = _get_jinja_env()

    async def generate(
        self,
        report_type: str | ReportType,
        scope: str = "",
        classification: str | ReportClassification = ReportClassification.AMBER,
        save: bool = True,
    ) -> CTIReport:
        if isinstance(report_type, str):
            report_type = ReportType(report_type.lower())
        if isinstance(classification, str):
            classification = ReportClassification(classification.upper())

        now = datetime.now(tz=UTC)
        period_start, period_end = _get_period(report_type, now)

        log.info("report.generate.start", report_type=report_type.value, scope=scope)

        report = CTIReport(
            report_type=report_type,
            title=f"CTI {report_type.value.capitalize()} Report — {now.strftime('%Y-%m-%d')}",
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            start_time=period_start,
            end_time=period_end,
            scope=scope,
            classification=classification,
        )

        # Collect intel from specialized agents in parallel
        gather_results: tuple[Any, ...] = await asyncio.gather(
            self._collect_ioc_intel(scope),
            self._collect_threat_actor_intel(scope),
            self._collect_vuln_intel(scope, report_type),
            return_exceptions=True,
        )
        ioc_result: Any = gather_results[0]
        ta_result: Any = gather_results[1]
        vuln_result: Any = gather_results[2]

        if not isinstance(ioc_result, Exception):
            report.ioc_summary = ioc_result
        if not isinstance(ta_result, Exception):
            report.threat_actor_summary = ta_result
        if not isinstance(vuln_result, Exception):
            report.vulnerability_summary = vuln_result

        # Generate narrative via ReportAgent; log failures but keep the report.
        try:
            report = await ReportAgent().run(report=report, scope=scope)
        except AgentError as e:
            log.error("report.narrative_failed", category=e.category, error=str(e))
            report.executive_summary = f"[Narrative generation failed: {e}]"

        # Render Jinja2 template
        report.content = self.render(report)

        if save:
            self._save(report)

        log.info("report.generate.done", report_type=report_type.value)
        return report

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
        alert_summary = await TriageAgent().run(alerts=alerts, context=context)
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
        report = await ReportAgent().run(report=report, scope=context)
        report.content = self.render(report)
        if save:
            self._save(report)
        return report

    async def _collect_ioc_intel(self, scope: str) -> Any:
        indicators = [s.strip() for s in scope.split(",") if s.strip()] if scope else []
        if not indicators:
            return IOCEnrichmentResult(
                indicators=[],
                summary="No IOC scope was provided for this report.",
            )
        return await IOCEnrichmentAgent().run(indicators=indicators)

    async def _collect_threat_actor_intel(self, scope: str) -> Any:
        query = scope if scope else "current top threat actors"
        return await ThreatActorAgent().run(query=query)

    async def _collect_vuln_intel(self, scope: str, report_type: ReportType) -> Any:
        threshold = "critical" if report_type in (ReportType.DAILY, ReportType.INCIDENT) else "high"
        return await VulnIntelAgent().run(
            keywords=scope or "critical",
            severity_threshold=threshold,
        )

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

        filename = f"{report.report_type.value}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.md"
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
