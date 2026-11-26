"""
AgentGuard — Three Agents
Each agent runs real logic and passes its actual output to the next agent.
Every protected tool call is routed through intercept_and_execute() (the interceptor).
"""

import time
import re
import uuid
from pathlib import Path
try:
    from .risk_engine import intercept_and_execute
except ImportError:  # Streamlit's script-directory import mode
    from risk_engine import intercept_and_execute

BASE_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = BASE_DIR / "sandbox"
OUTPUT_DIR = BASE_DIR / "output"
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Research data (local sample dataset) ─────────────────────────────────────
EV_RESEARCH_DATA = {
    "LFP": {
        "full_name": "Lithium Iron Phosphate",
        "energy_density": "160–180 Wh/kg",
        "cycle_life": "3,000+ cycles",
        "thermal_runaway_temp": "~270°C",
        "fast_charge": "20–25 min (10–80%)",
        "notes": "Excellent thermal stability; low raw-material cost; ideal for standard-range EVs.",
    },
    "NMC811": {
        "full_name": "Nickel Manganese Cobalt 811",
        "energy_density": "250–300 Wh/kg",
        "cycle_life": "1,500–2,000 cycles",
        "thermal_runaway_temp": "~210°C",
        "fast_charge": "18–22 min (10–80%)",
        "notes": "High energy density; preferred for long-range performance EVs.",
    },
    "SolidState": {
        "full_name": "Solid-State Battery",
        "energy_density": "400+ Wh/kg",
        "cycle_life": "2,500+ cycles",
        "thermal_runaway_temp": "Non-flammable",
        "fast_charge": "10–12 min (10–80%)",
        "notes": "Solid ceramic electrolyte; no thermal-runaway risk; commercial pilot by 2027–2030.",
    },
}

KEY_FINDINGS = [
    "Silicon-anode integration delivers ~20% higher volumetric capacity vs graphite anodes.",
    "Solid-state batteries projected for pilot production between 2027 and 2030.",
    "Closed-loop hydrometallurgical recycling recovers >95% of lithium, cobalt, and nickel.",
    "LFP dominates the standard-range EV market due to cost and safety advantages.",
    "Fast-charging infrastructure (>350 kW DC) is the main bottleneck for NMC adoption.",
]


class _BaseAgent:
    """All agent tools pass through the shared intercept_and_execute boundary."""

    def __init__(self, agent_id: str, role: str, task: str, task_id: str = None,
                 task_context: dict = None):
        self.agent_id = agent_id
        self.role = role
        self.task = task
        self.task_id = task_id or f"task-{uuid.uuid4()}"
        self.task_context = dict(task_context or {})
        self.history = {"actions_count": 0, "avg_risk": 10.0}
        self.action_log: list[dict] = []
        self.status = "IDLE"

    def _call_tool(self, tool: str, resource: str,
                   destination: str = "none", data_sensitivity: float = 0.0,
                   payload: dict = None) -> dict:
        """
        MANDATORY interceptor — every tool call MUST go through this method.
        Returns the evaluate_action result including decision.
        """
        def execute():
            if tool == "search_data":
                document = (SANDBOX_DIR / "ev_battery_notes.txt").read_text(encoding="utf-8")
                if not any(term in self.task.lower() for term in ("battery", "electric", "ev", "lithium")):
                    return ""
                return document
            if tool == "extract_information":
                text = (SANDBOX_DIR / "ev_battery_notes.txt").read_text(encoding="utf-8")
                chemistries, key_findings, source_lines, data_gaps = _parse_research_dataset(text)
                return {"dataset_text": text, "chemistries": chemistries,
                        "key_findings": key_findings, "source_lines": source_lines,
                        "data_gaps": data_gaps}
            if tool == "read_file":
                return (SANDBOX_DIR / Path(resource).name).read_text(encoding="utf-8")
            if tool == "analyze_data":
                return _analyze_findings((payload or {})["findings"])
            if tool == "compile_report":
                return _build_report((payload or {})["analysis"], (payload or {}).get("user_task", ""))
            if tool == "validate_provenance":
                claims = (payload or {}).get("unverified_claims", [])
                return {"claims_checked": (payload or {}).get("claim_count", 0),
                        "unverified_claims": claims}
            if tool == "write_file":
                text = (payload or {}).get("content", "")
                base = OUTPUT_DIR if destination == "output" else SANDBOX_DIR
                path = base / Path(resource).name
                path.write_text(text, encoding="utf-8")
                return str(path)
            return {"completed": True}

        result = intercept_and_execute(
            agent=self.role,
            task=self.task,
            tool=tool,
            resource=resource,
            destination=destination,
            data_sensitivity=data_sensitivity,
            agent_history=self.history,
            executor=execute,
            task_id=self.task_id,
            task_context=self.task_context,
            payload=payload,
        )
        self.history["actions_count"] += 1
        prev_avg = self.history["avg_risk"]
        n = self.history["actions_count"]
        self.history["avg_risk"] = round((prev_avg * (n - 1) + result["risk_score"]) / n, 1)
        self.action_log.append(result)
        return result


# ── Research Agent ─────────────────────────────────────────────────────────────
class ResearchAgent(_BaseAgent):
    """Collects EV battery research from the local dataset and approved sandbox file."""

    def __init__(self, task: str = "Research EV battery technology and generate a report", task_id: str = None,
                 task_context: dict = None):
        super().__init__("research_01", "ResearchAgent", task, task_id, task_context)

    def run(self) -> dict:
        self.status = "RUNNING"
        events = []

        # Step 1: Search approved dataset
        r1 = self._call_tool("search_data", "ev_battery_notes.txt")
        events.append(r1)

        if r1["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r1)
            return {"status": self.status, "events": events, "findings": None}
        if not r1.get("tool_result"):
            self.status = "TASK_FAILURE"
            return {"status": "TASK_FAILURE", "events": events, "findings": None}

        # Step 2: Extract information from approved file
        r2 = self._call_tool("extract_information", "research_data.txt", data_sensitivity=5.0)
        events.append(r2)
        if r2["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r2)
            return {"status": self.status, "events": events, "findings": None}

        # Compile actual research output
        extracted = r2.get("tool_result") or {}
        dataset_text = extracted.get("dataset_text", "")
        if not dataset_text.strip():
            self.status = "TASK_FAILURE"
            return {"status": "TASK_FAILURE", "events": events, "findings": None}
        findings = {
            "chemistries": extracted["chemistries"],
            "key_findings": extracted["key_findings"],
            "source_lines": extracted.get("source_lines", {}),
            "data_gaps": extracted.get("data_gaps", []),
            "sources": ["local research dataset", "ev_battery_notes.txt"],
            "dataset_text": dataset_text,
        }

        # Step 3: Write research findings to sandbox
        r3 = self._call_tool("write_file", "research_findings.txt", data_sensitivity=5.0,
                             payload={"content": _format_research(findings)})
        events.append(r3)

        if r3["decision"] != "ALLOW":
            self.status = _stopped_status(r3)
            return {"status": self.status, "events": events, "findings": None}

        self.status = "COMPLETED"
        return {"status": "COMPLETED", "events": events, "findings": findings}


# ── Analysis Agent ─────────────────────────────────────────────────────────────
class AnalysisAgent(_BaseAgent):
    """Processes research findings: summarises, compares, highlights key points."""

    def __init__(self, task: str = "Analyze research data for EV battery technology", task_id: str = None,
                 task_context: dict = None):
        super().__init__("analysis_01", "AnalysisAgent", task, task_id, task_context)

    def run(self, findings: dict) -> dict:
        self.status = "RUNNING"
        events = []

        # Step 1: Read research findings
        r1 = self._call_tool("read_file", "research_findings.txt", data_sensitivity=5.0)
        events.append(r1)

        if r1["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r1)
            return {"status": self.status, "events": events, "analysis": None}

        # Step 2: Analyse data
        r2 = self._call_tool("analyze_data", "research_findings.txt", data_sensitivity=10.0,
                             payload={"findings": findings})
        events.append(r2)
        if r2["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r2)
            return {"status": self.status, "events": events, "analysis": None}

        analysis = r2["tool_result"]

        # Step 3: Write analysis output
        r3 = self._call_tool("write_file", "analysis_output.txt", data_sensitivity=10.0,
                             payload={"content": _format_analysis(analysis)})
        events.append(r3)

        if r3["decision"] != "ALLOW":
            self.status = _stopped_status(r3)
            return {"status": self.status, "events": events, "analysis": None}

        self.status = "COMPLETED"
        return {"status": "COMPLETED", "events": events, "analysis": analysis}


# ── Report Agent ───────────────────────────────────────────────────────────────
class ReportAgent(_BaseAgent):
    """Compiles a Markdown report from the analysis output and saves it to /output."""

    def __init__(self, task: str = "Generate final report for EV battery technology", task_id: str = None,
                 task_context: dict = None):
        super().__init__("report_01", "ReportAgent", task, task_id, task_context)

    def run(self, analysis: dict, user_task: str = "") -> dict:
        self.status = "RUNNING"
        events = []

        # Step 1: Read analysis file
        r1 = self._call_tool("read_file", "analysis_output.txt", data_sensitivity=10.0)
        events.append(r1)

        if r1["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r1)
            return {"status": self.status, "events": events, "report_path": None, "report_content": None}

        # Step 2: Compile report
        r2 = self._call_tool("compile_report", "ev_battery_report.md", data_sensitivity=5.0,
                             payload={"analysis": analysis, "user_task": user_task})
        events.append(r2)

        if r2["execution_status"] != "EXECUTED":
            self.status = _stopped_status(r2)
            return {"status": self.status, "events": events, "report_path": None, "report_content": None}

        report_md = r2["tool_result"]

        unverified = analysis.get("unverified_claims", [])
        if unverified:
            provenance = self._call_tool(
                "validate_provenance", "approved_research_dataset",
                payload={"claim_count": len(analysis.get("raw_findings", [])) + len(unverified),
                         "unverified_claims": unverified,
                         "unsupported_claim": "; ".join(item["text"] for item in unverified)},
            )
            events.append(provenance)

        # Step 3: Write report to output folder
        ts = time.strftime("%Y%m%d_%H%M%S")
        fname = f"report_{ts}.md"
        r3 = self._call_tool("write_file", fname,
                              destination="output", data_sensitivity=5.0,
                              payload={"content": report_md})
        events.append(r3)

        report_path = None
        if r3["decision"] == "ALLOW" and r3.get("execution_status") == "EXECUTED":
            report_path = Path(r3["tool_result"])
        else:
            self.status = _stopped_status(r3)
            return {"status": self.status, "events": events, "report_path": None, "report_content": None}

        self.status = "COMPLETED"
        return {
            "status": "COMPLETED",
            "events": events,
            "report_path": report_path,
            "report_content": report_md,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────
def _stopped_status(result: dict) -> str:
    if result["decision"] == "BLOCK":
        return "BLOCKED"
    if result["decision"] == "ASK":
        return "WAITING_APPROVAL"
    return "TASK_FAILURE"


def _analyze_findings_legacy(findings: dict) -> dict:
    chemistries = findings.get("chemistries", {})
    source_text = findings.get("dataset_text", "")
    key_points = [
        f"{value['full_name']}: " + "; ".join(
            f"{label}: {value[field]}" for label, field in
            (("Energy density", "energy_density"), ("Cycle life", "cycle_life"), ("Thermal note", "thermal"))
            if value.get(field) and value[field] != "Not stated in local notes"
        ) for value in chemistries.values()
    ] + findings.get("key_findings", [])
    return {
        "summary": "The local research notes describe " + ", ".join(
            value["full_name"] for value in chemistries.values()
        ) + ". This analysis reports only facts stated in the included dataset. Source excerpt: " + source_text[:350],
        "key_points": key_points,
        "recommendation": "The included notes do not provide comparable cost and charging data; use this as a summary, not a purchasing recommendation.",
        "raw_findings": findings.get("key_findings", []),
        "chemistries": chemistries,
    }


def _parse_research_dataset_legacy(text: str):
    """Extract only facts present in the offline research notes."""
    chemistries = {}
    key_findings = []
    for line in text.splitlines():
        match = re.match(r"\s*\d+\.\s+(.+?)\s+\(([^)]+)\):\s*(.*)", line)
        if match:
            name, code, details = match.groups()
            density = re.search(r"\d[\d,]*(?:[–-]\d[\d,]*)?\+?\s*Wh/kg", details, re.I)
            cycles = re.search(r"\d[\d,]*\+?\s*cycles", details, re.I)
            thermal = re.search(r"thermal stability\s*~?\d+\s*°?C?", details, re.I)
            chemistries[code] = {
                "full_name": name.strip(),
                "energy_density": density.group(0) if density else "Not stated in local notes",
                "cycle_life": cycles.group(0) if cycles else "Not stated in local notes",
                "thermal": thermal.group(0) if thermal else (
                    "Non-flammable" if "non-flammable" in details.lower() else "Not stated in local notes"
                ),
                "notes": details.strip(),
            }
        elif line.strip().startswith("-"):
            key_findings.append(line.strip().lstrip("- "))
    return chemistries, key_findings


def _format_research(findings: dict) -> str:
    lines = ["# Research Agent Findings\n"]
    for k, v in findings["chemistries"].items():
        lines.append(f"## {v['full_name']}")
        lines.append(f"- Energy Density: {v['energy_density']}")
        lines.append(f"- Cycle Life: {v['cycle_life']}")
        lines.append(f"- Thermal note: {v['thermal']}")
        lines.append(f"- Notes: {v['notes']}\n")
    lines.append("## Key Findings")
    for f in findings["key_findings"]:
        lines.append(f"- {f}")
    return "\n".join(lines)


def _format_analysis(analysis: dict) -> str:
    lines = ["# Analysis Agent Output\n",
             f"**Summary**: {analysis['summary']}\n",
             "## Key Points"]
    for p in analysis["key_points"]:
        lines.append(f"- {p}")
    lines.append(f"\n**Recommendation**: {analysis['recommendation']}")
    return "\n".join(lines)


def _build_report_legacy(analysis: dict, user_task: str) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    chem = analysis.get("chemistries", {})
    kp = analysis.get("key_points", [])
    rf = analysis.get("raw_findings", [])
    summary = analysis.get("summary", "")
    recommendation = analysis.get("recommendation", "")

    table_rows = "\n".join(
        f"| **{v['full_name']}** | {v.get('energy_density', 'Not stated')} | {v.get('cycle_life', 'Not stated')} "
        f"| {v.get('thermal', 'Not stated')} | Not stated |"
        for v in chem.values()
    )

    return f"""# 🔋 Research Report: Electric Vehicle Battery Technology

**Task**: {user_task or "Research EV battery technology and generate a report"}
**Date**: {ts}
**Generated By**: AgentGuard Multi-Agent System
  → ResearchAgent → AnalysisAgent → ReportAgent
**Security Status**: 🟢 ALL ACTIONS EVALUATED BY AgentGuard

---

## Executive Summary

{summary}

---

## 1. Battery Chemistry Comparison

| Chemistry | Energy Density | Cycle Life | Thermal Safety | Fast Charge (10–80%) |
|:---|:---|:---|:---|:---|
{table_rows}

---

## 2. Analysis Agent Key Points

{chr(10).join(f"- {p}" for p in kp)}

---

## 3. Research Findings

{chr(10).join(f"{i+1}. {f}" for i, f in enumerate(rf))}

---

## 4. Recommendation

{recommendation}

---

*This report was generated and validated by the AgentGuard Security Layer.*
*All agent actions were intercepted, evaluated, and approved before execution.*
"""


# Source-aware implementations supersede the original prototype helpers above.
def _parse_research_dataset(text: str):
    chemistries, key_findings, source_lines, gaps = {}, [], {}, set()
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"\s*\d+\.\s+(.+?)(?:\s+\(([^)]+)\))?:\s*(.*)", line)
        if match:
            name, code, details = match.groups()
            compact = re.sub(r"[^a-z0-9]", "", name.lower())
            code = code or ("NMC811" if "nmc" in compact else "SolidState" if "solidstate" in compact else re.sub(r"\W", "", name))
            density = re.search(r"\d[\d,]*(?:[-–]\d[\d,]*)?\+?\s*Wh/kg", details, re.I)
            cycles = re.search(r"\d[\d,]*(?:[-–]\d[\d,]*)?\+?\s*cycles", details, re.I)
            thermal = re.search(r"thermal stability\s*~?\d+\s*°?C?", details, re.I)
            fast = re.search(r"\d+[-–]\d+\s*min(?:utes)?(?:\s*\(10[-–]80%\))?", details, re.I)
            commercial = re.search(r"commercial(?:\s+pilot)?\s+by\s+\d{4}(?:[-–]\d{4})?", details, re.I)
            if not density: gaps.add(f"Energy density for {name.strip()}")
            if not cycles: gaps.add(f"Cycle life for {name.strip()}")
            if not thermal and "non-flammable" not in details.lower(): gaps.add(f"Thermal safety for {name.strip()}")
            if not fast: gaps.add(f"Fast-charge time for {name.strip()}")
            source = {"line": line_number, "text": line.strip()}
            chemistries[code] = {"full_name": name.strip(),
                "energy_density": density.group(0) if density else None,
                "cycle_life": cycles.group(0) if cycles else None,
                "thermal": thermal.group(0) if thermal else ("Non-flammable" if "non-flammable" in details.lower() else None),
                "fast_charge": fast.group(0) if fast else None,
                "commercialization": commercial.group(0) if commercial else None,
                "notes": details.strip(), "source": source}
            source_lines[name.strip()] = source
        elif line.strip().startswith("-"):
            finding = line.strip().lstrip("- ")
            key_findings.append(finding)
            source_lines[finding] = {"line": line_number, "text": line.strip()}
    if "cost" not in text.lower(): gaps.add("Battery cost")
    if not any("fast" in key.lower() and "charge" in key.lower() for key in source_lines):
        gaps.add("Comparable fast-charge times")
    return chemistries, key_findings, source_lines, sorted(gaps)


def _analyze_findings(findings: dict) -> dict:
    chemistries = findings.get("chemistries", {})
    supported, unverified = [], []
    for point in findings.get("key_findings", []):
        item = {"text": point, "source": findings.get("source_lines", {}).get(point)}
        (supported if item["source"] else unverified).append(item)
    summary = ("The approved dataset documents " + "; ".join(
        f"{v['full_name']} (source line {v['source']['line']})" for v in chemistries.values()
    ) + ".") if chemistries else "No chemistry was parsed from the approved dataset."
    return {"summary": summary, "key_points": [x["text"] for x in supported],
        "recommendation": "Use this as a summary of the approved local dataset; it does not support a purchasing recommendation.",
        "raw_findings": supported, "unverified_claims": unverified,
        "chemistries": chemistries, "data_gaps": findings.get("data_gaps", [])}


def _build_report(analysis: dict, user_task: str) -> str:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    chemistries = analysis.get("chemistries", {})
    claims = list(analysis.get("raw_findings", [])) + list(analysis.get("unverified_claims", []))
    total = len(chemistries) + len(claims)
    traced = len([v for v in chemistries.values() if v.get("source")]) + len([c for c in claims if c.get("source")])
    rows = []
    for item in chemistries.values():
        source = item.get("source") or {}
        cite = f"[line {source['line']}]" if source.get("line") else "UNVERIFIED"
        rows.append(f"| {item['full_name']} | {item.get('energy_density') or '—'} | {item.get('cycle_life') or '—'} | {item.get('thermal') or '—'} | {item.get('fast_charge') or '—'} | {item.get('commercialization') or '—'} | {cite} |")
    key_rows = []
    for claim in claims:
        source = claim.get("source") or {}
        citation = f"[Source line {source['line']}]" if source.get("line") else "**UNVERIFIED — provenance incident recorded**"
        key_rows.append(f"- {claim['text']} — {citation}")
    gaps = set(analysis.get("data_gaps", []))
    if not any("cost" in gap.lower() for gap in gaps):
        gaps.add("Battery cost and comparable cost basis")
    gaps = sorted(gaps)
    unverified_rows = [f"- {c['text']} — UNVERIFIED" for c in analysis.get("unverified_claims", [])]
    unverified_section = "\n".join(unverified_rows) if unverified_rows else "None identified in the analyzed claims."
    return f"""# EV Battery Technology Research Report

**Task:** {user_task or 'Research EV battery technology and generate a report'}  
**Generated:** {timestamp}  
**Workflow:** ResearchAgent → AnalysisAgent → ReportAgent  
**Permissions:** {analysis.get('permission_status', 'PASSED')} (gateway decisions)  
**Output provenance:** {traced} of {total} claims traced to approved sources

## Executive summary

{analysis.get('summary', 'No structured summary was available.')}

## Battery chemistry comparison

| Chemistry | Energy density | Cycle life | Thermal safety | Fast-charge time | Commercial timing | Source |
|:--|:--|:--|:--|:--|:--|:--|
{chr(10).join(rows)}

## Findings

{chr(10).join(key_rows) if key_rows else 'No additional dataset findings were extracted.'}

## Data gaps

The approved dataset does not provide:
{chr(10).join('- ' + gap for gap in gaps)}

## Unverified claims

{unverified_section}

## Recommendation

{analysis.get('recommendation', 'Treat this as a summary of the local dataset, not a purchasing recommendation.')}
"""
