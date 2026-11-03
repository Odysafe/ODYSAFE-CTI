"""Excel renderer for ODYSAFE Profiles & Clusters preview exports."""

from datetime import datetime, timezone
from io import BytesIO

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


NAVY = "243247"
BLUE = "DCE9F7"
PURPLE = "E9E2F5"
ORANGE = "FCE8D2"
GREEN = "DDF0E5"
RED = "F7D7D7"
GRAY = "EEF1F5"
WHITE = "FFFFFF"
TEXT = "172033"
MUTED = "667085"
THIN = Side(style="thin", color="CDD5DF")
MAX_CELL = 32000


def safe_cell(value):
    """Keep exported content as safe spreadsheet text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        value = ", ".join(safe_cell(item) for item in value if item is not None)
    if isinstance(value, dict):
        value = ", ".join(f"{key}: {safe_cell(item)}" for key, item in value.items() if item is not None)
    text = str(value).replace("\x00", "")[:MAX_CELL]
    if text.startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def _as_list(value):
    return value if isinstance(value, list) else []


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _nonempty(rows):
    return [row for row in _as_list(rows) if isinstance(row, dict) and any(str(v or "").strip() for v in row.values())]


def _count_values(rows, key, default="UNKNOWN"):
    counts = {}
    for row in _nonempty(rows):
        value = safe_cell(row.get(key) or default).strip() or default
        counts[value] = counts.get(value, 0) + 1
    return [{"label": label, "count": count} for label, count in sorted(counts.items())]


def _style_title(ws, title, subtitle, columns):
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=columns)
    cell = ws.cell(1, 1, safe_cell(title))
    cell.fill = PatternFill("solid", fgColor=NAVY)
    cell.font = Font(size=18, bold=True, color=WHITE)
    cell.alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 34

    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=columns)
    meta = ws.cell(2, 1, safe_cell(subtitle))
    meta.fill = PatternFill("solid", fgColor=GRAY)
    meta.font = Font(size=10, bold=True, color=TEXT)
    meta.alignment = Alignment(wrap_text=True)

    ws.freeze_panes = "A4"
    ws.sheet_view.showGridLines = False
    ws.oddFooter.right.text = "Exported UTC " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    return 4


def _section(ws, row, title, columns, color=BLUE):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=columns)
    cell = ws.cell(row, 1, safe_cell(title))
    cell.fill = PatternFill("solid", fgColor=color)
    cell.font = Font(size=11, bold=True, color=TEXT)
    cell.border = Border(bottom=THIN)
    return row + 1


def _fields(ws, row, values, columns):
    for label, value in values:
        ws.cell(row, 1, safe_cell(label)).font = Font(bold=True, color=TEXT)
        ws.cell(row, 1).border = Border(bottom=THIN)
        ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=columns)
        cell = ws.cell(row, 2, safe_cell(value) or "Not provided")
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        cell.border = Border(bottom=THIN)
        ws.row_dimensions[row].height = max(22, min(96, 18 + len(str(value or "")) // 12))
        row += 1
    return row


def _table(ws, row, title, rows, columns, color=PURPLE):
    row = _section(ws, row, title, len(columns), color)
    rows = _nonempty(rows)
    if not rows:
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=len(columns))
        ws.cell(row, 1, "No data provided.").font = Font(italic=True, color=MUTED)
        return row + 2
    header_row = row
    for col, (_, label) in enumerate(columns, 1):
        cell = ws.cell(row, col, label)
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.font = Font(bold=True, color=WHITE)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
    row += 1
    for idx, item in enumerate(rows):
        for col, (key, _) in enumerate(columns, 1):
            cell = ws.cell(row, col, safe_cell(item.get(key, "")))
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = Border(left=THIN, right=THIN, bottom=THIN)
            if idx % 2:
                cell.fill = PatternFill("solid", fgColor="F8FAFC")
        ws.row_dimensions[row].height = 34
        row += 1
    ws.auto_filter.ref = f"A{header_row}:{get_column_letter(len(columns))}{row - 1}"
    return row + 2


def _set_widths(ws, widths):
    for index, width in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(index)].width = width


def _finish(ws, widths=None):
    widths = widths or {}
    for index in range(1, ws.max_column + 1):
        letter = get_column_letter(index)
        estimated = max(
            (len(str(ws.cell(row, index).value or "")) for row in range(1, min(ws.max_row, 250) + 1)),
            default=10,
        ) + 2
        ws.column_dimensions[letter].width = min(widths.get(letter, max(12, estimated)), 46)
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.print_title_rows = "1:3"


def _visual_status_table(ws, row, title, rows, columns=8):
    row = _section(ws, row, title, columns, PURPLE)
    rows = _nonempty(rows)
    if not rows:
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=columns)
        ws.cell(row, 1, "No data provided.").font = Font(italic=True, color=MUTED)
        return row + 2
    max_count = max((int(item.get("count") or 0) for item in rows), default=1) or 1
    for col, label in enumerate(("Status", "Count", "Visual"), 1):
        cell = ws.cell(row, col, label)
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.font = Font(bold=True, color=WHITE)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
    row += 1
    for item in rows:
        label = safe_cell(item.get("label"))
        count = int(item.get("count") or 0)
        blocks = max(1 if count else 0, round((count / max_count) * 18))
        ws.cell(row, 1, label)
        ws.cell(row, 2, count)
        bar = ws.cell(row, 3, ("█" * blocks) + (f"  {count}" if count else "  0"))
        bar.font = Font(color="2563EB", bold=True)
        bar.alignment = Alignment(vertical="center")
        for col in range(1, 4):
            ws.cell(row, col).border = Border(left=THIN, right=THIN, bottom=THIN)
            if row % 2:
                ws.cell(row, col).fill = PatternFill("solid", fgColor="F8FAFC")
        ws.row_dimensions[row].height = 22
        row += 1
    return row + 2


def _write_notice(ws, row, text, columns, color=ORANGE):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=columns)
    cell = ws.cell(row, 1, safe_cell(text))
    cell.fill = PatternFill("solid", fgColor=color)
    cell.font = Font(bold=True, color=TEXT)
    cell.alignment = Alignment(wrap_text=True, vertical="top")
    cell.border = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
    ws.row_dimensions[row].height = 42
    return row + 2


def _profile_from_payload(payload):
    if "profile" in payload and isinstance(payload.get("profile"), dict):
        candidate = payload.get("profile")
        if isinstance(candidate.get("profile"), dict):
            return candidate
        if candidate.get("profile_id"):
            return {"profile": candidate}
        return payload
    profiles = _as_list(payload.get("profiles"))
    return profiles[0] if profiles else {}


def _profile_summary_row(export):
    profile = _as_dict(export.get("profile"))
    counters = _as_dict(profile.get("counters"))
    return {
        "profile_id": profile.get("profile_id"),
        "name": profile.get("display_name"),
        "type": profile.get("profile_type"),
        "workflow_status": profile.get("workflow_status"),
        "activity_state": profile.get("activity_state"),
        "analytic_confidence": profile.get("analytic_confidence"),
        "internal_relevance": profile.get("internal_relevance"),
        "internal_attribution_status": profile.get("internal_attribution_status"),
        "first_seen": profile.get("first_seen"),
        "last_seen": profile.get("last_seen"),
        "open_gaps": counters.get("gaps"),
    }


def _profile_kpis(profile, export):
    members = _nonempty(export.get("memberships"))
    gaps = _as_list(export.get("gaps"))
    evidence = _nonempty(export.get("evidence"))
    sources = _as_list(export.get("sources"))
    judgements = _as_list(profile.get("key_judgements"))
    open_gaps = len([gap for gap in gaps if str(_as_dict(gap).get("status") or "OPEN").upper() == "OPEN"])
    return [
        ("Members", len(members)),
        ("Sources", len(sources)),
        ("Evidence", len(evidence)),
        ("Key Judgements", len(judgements)),
        ("Open Gaps", open_gaps),
    ]


def _dashboard(wb, export, collection, is_demo):
    profile = _as_dict(export.get("profile"))
    reference = profile.get("profile_id") or "profiles-clusters"
    ws = wb.active
    ws.title = "Dashboard"
    row = _style_title(ws, "PROFILES & CLUSTERS DASHBOARD", f"{reference} | {'Demo template' if is_demo else 'Analyst workspace'}", 9)
    notice = "DEMO DATA — Synthetic examples only. Do not treat this workbook as validated intelligence." if is_demo else "Analyst workspace export — Review before operational use."
    row = _write_notice(ws, row, notice, 9, ORANGE if is_demo else GREEN)
    row = _section(ws, row, "Profile Control", 9)
    row = _fields(ws, row, [
        ("Profile ID", profile.get("profile_id")),
        ("Display Name", profile.get("display_name")),
        ("Profile Type", profile.get("profile_type")),
        ("Workflow Status", profile.get("workflow_status")),
        ("Activity State", profile.get("activity_state")),
        ("Analytic Confidence", profile.get("analytic_confidence")),
        ("Internal Relevance", profile.get("internal_relevance")),
        ("Internal Attribution Status", profile.get("internal_attribution_status")),
        ("Created From Workspace", profile.get("created_from_workspace")),
    ], 9)
    row += 1
    row = _section(ws, row, "Operational KPIs", 9)
    for col, (label, count) in enumerate(_profile_kpis(profile, export), 1):
        cell = ws.cell(row, col, f"{label}\n{count}")
        cell.fill = PatternFill("solid", fgColor=GRAY)
        cell.font = Font(bold=True, color=TEXT)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
    ws.row_dimensions[row].height = 48
    row += 2
    row = _section(ws, row, "Assessment Snapshot", 9, GREEN)
    row = _fields(ws, row, [
        ("Purpose / Tracking Question", profile.get("purpose")),
        ("Description", profile.get("description")),
        ("Assessment", profile.get("assessment")),
        ("Confidence Rationale", profile.get("confidence_rationale")),
    ], 9)
    row = _visual_status_table(ws, row, "Membership Status", _count_values(export.get("memberships"), "status", "UNKNOWN"), 9)
    row = _visual_status_table(ws, row, "Member Confidence", _count_values(export.get("memberships"), "confidence", "UNKNOWN"), 9)
    row = _visual_status_table(ws, row, "Gap Status", _count_values(export.get("gaps"), "status", "OPEN"), 9)
    if collection:
        row = _visual_status_table(ws, row, "Collection Workflow Status", _count_values([_as_dict(item.get("profile")) for item in collection], "workflow_status", "OPEN"), 9)
    _finish(ws, {"A": 28, "B": 32, "C": 32})


def build_workbook(payload):
    """Build an XLSX workbook from a Profiles & Clusters export payload."""
    export = _profile_from_payload(payload)
    collection = _as_list(payload.get("profiles"))
    profile = _as_dict(export.get("profile"))
    reference = profile.get("profile_id") or "profiles-clusters"
    is_demo = bool(export.get("demo_data") or payload.get("demo_data"))
    subtitle = f"{reference} | {'Demo template export' if is_demo else 'Analyst workspace export'}"

    wb = Workbook()
    _dashboard(wb, export, collection, is_demo)

    summary = wb.create_sheet("Executive Summary")
    row = _style_title(summary, "ODYSAFE Profiles & Clusters", subtitle, 8)
    if is_demo:
        row = _write_notice(summary, row, "DEMO DATA — Synthetic examples only. Do not treat this workbook as validated intelligence.", 8)
    else:
        row = _write_notice(summary, row, "Analyst workspace export — Data was maintained in the browser workspace and should be reviewed before operational use.", 8, GREEN)
    row = _section(summary, row, "Profile Overview", 8, BLUE)
    row = _fields(summary, row, [
        ("Profile ID", profile.get("profile_id")),
        ("Name", profile.get("display_name")),
        ("Profile Type", profile.get("profile_type")),
        ("Workflow Status", profile.get("workflow_status")),
        ("Activity State", profile.get("activity_state")),
        ("Overall Analytic Confidence", profile.get("analytic_confidence")),
        ("Confidence Rationale", profile.get("confidence_rationale")),
        ("Internal Relevance", profile.get("internal_relevance")),
        ("Internal Attribution Status", profile.get("internal_attribution_status")),
        ("External Reporting", profile.get("external_reporting")),
        ("First Seen", profile.get("first_seen")),
        ("Last Seen", profile.get("last_seen")),
        ("Created From Workspace", profile.get("created_from_workspace")),
    ], 8)
    row += 1
    row = _section(summary, row, "Assessment", 8, GREEN)
    row = _fields(summary, row, [
        ("Purpose / Tracking Question", profile.get("purpose")),
        ("Description", profile.get("description")),
        ("Assessment", profile.get("assessment")),
        ("Temporal Scope", _as_dict(profile.get("scope")).get("temporal")),
        ("Geographic Scope", _as_dict(profile.get("scope")).get("geographic")),
        ("Sector Scope", _as_dict(profile.get("scope")).get("sector")),
        ("Technical Scope", _as_dict(profile.get("scope")).get("technical")),
        ("Excluded", _as_dict(profile.get("scope")).get("excluded")),
    ], 8)
    _finish(summary, {"A": 26, "B": 42, "C": 22, "D": 22, "E": 22, "F": 22, "G": 22, "H": 22})

    if collection:
        ws = wb.create_sheet("Profiles")
        row = _style_title(ws, "Profiles & Clusters Index", f"Collection export | {'Demo templates' if is_demo else 'Analyst workspace'}", 11)
        _table(ws, row, "Profiles", [_profile_summary_row(item) for item in collection], [
            ("profile_id", "Profile ID"),
            ("name", "Name"),
            ("type", "Type"),
            ("workflow_status", "Workflow Status"),
            ("activity_state", "Activity State"),
            ("analytic_confidence", "Analytic Confidence"),
            ("internal_relevance", "Internal Relevance"),
            ("internal_attribution_status", "Internal Attribution"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
            ("open_gaps", "Open Gaps"),
        ])
        _finish(ws, {"A": 22, "B": 32, "C": 24, "D": 20, "E": 20, "F": 22, "G": 20, "H": 24, "I": 16, "J": 16, "K": 14})

    ws = wb.create_sheet("Memberships")
    row = _style_title(ws, "Profile Memberships", f"{reference} | contextual memberships", 13)
    row = _write_notice(ws, row, "Membership Status describes association basis, not global maliciousness. Artifact Context is contextual to this profile.", 13)
    _table(ws, row, "Members", _as_list(export.get("memberships")), [
        ("id", "Membership ID"),
        ("value", "Member"),
        ("type", "Type"),
        ("role", "Role"),
        ("status", "Membership Status"),
        ("artifact_context", "Artifact Context"),
        ("confidence", "Confidence"),
        ("rationale", "Rationale"),
        ("source_refs", "Source Ref"),
        ("evidence_refs", "Evidence Ref"),
        ("first_seen", "First Seen"),
        ("last_seen", "Last Seen"),
        ("last_validated", "Last Validated"),
    ])
    _finish(ws, {"A": 18, "B": 34, "C": 16, "D": 22, "E": 22, "F": 24, "G": 16, "H": 50, "I": 22, "J": 22, "K": 16, "L": 16, "M": 18})

    ws = wb.create_sheet("Evidence & Sources")
    row = _style_title(ws, "Evidence & Sources", f"{reference} | source count is not corroboration", 8)
    row = _write_notice(ws, row, "Source count does not equal independent confirmation count. External reporting does not automatically become ODYSAFE attribution.", 8)
    row = _table(ws, row, "Sources", [
        {"name": s[0], "type": s[1], "tlp": s[2], "reliability": s[3]} if isinstance(s, list) else s
        for s in _as_list(export.get("sources"))
    ], [("name", "Name"), ("type", "Type"), ("tlp", "TLP"), ("reliability", "Reliability")], BLUE)
    row = _table(ws, row, "Evidence Register", _as_list(export.get("evidence")), [
        ("id", "Evidence ID"),
        ("type", "Type"),
        ("description", "Description"),
        ("source_ref", "Source Ref"),
        ("observed_at", "Observed At"),
        ("integrity", "Integrity"),
    ], PURPLE)
    _finish(ws, {"A": 22, "B": 22, "C": 54, "D": 22, "E": 24, "F": 34, "G": 20, "H": 20})

    ws = wb.create_sheet("Behavior")
    row = _style_title(ws, "Behavior", f"{reference} | ATT&CK, tools, and malware", 8)
    row = _write_notice(ws, row, "ATT&CK overlap describes behavioral similarity only and does not establish attribution.", 8)
    row = _table(ws, row, "TTPs", _as_list(export.get("ttps")), [
        ("technique_id", "Technique ID"),
        ("name", "Technique Name"),
        ("procedure", "Procedure"),
        ("phase", "Phase"),
        ("seen", "First / Last Seen"),
        ("confidence", "Confidence"),
        ("source_ref", "Source Ref"),
    ], BLUE)
    row = _table(ws, row, "Tools & Malware", _as_list(export.get("tools")), [
        ("name", "Name"),
        ("type", "Type"),
        ("description", "Description"),
    ], PURPLE)
    _finish(ws, {"A": 20, "B": 28, "C": 58, "D": 22, "E": 22, "F": 16, "G": 28, "H": 24})

    ws = wb.create_sheet("Analysis")
    row = _style_title(ws, "Analysis", f"{reference} | discriminators, gaps, and claims", 5)
    row = _table(ws, row, "Key Discriminators", [
        {"value": item[0], "weight": item[1], "rationale": item[2]} if isinstance(item, list) else item
        for item in _as_list(profile.get("key_discriminators"))
    ], [("value", "Value"), ("weight", "Weight"), ("rationale", "Rationale")], GREEN)
    row = _table(ws, row, "Key Judgements", [
        {"judgement": item[2], "status": item[0], "confidence": item[1], "evidence_refs": item[3] if len(item) > 3 else ""} if isinstance(item, list) else item
        for item in _as_list(profile.get("key_judgements"))
    ], [("judgement", "Judgement"), ("status", "Status"), ("confidence", "Confidence"), ("evidence_refs", "Evidence Refs")], BLUE)
    row = _table(ws, row, "Exclusion Criteria", [{"criterion": item} for item in _as_list(profile.get("exclusion_criteria"))], [("criterion", "Criterion")], ORANGE)
    row = _table(ws, row, "Open Gaps", [
        {"question": item[0], "priority": item[1], "status": item[2]} if isinstance(item, list) else item
        for item in _as_list(export.get("gaps"))
    ], [("question", "Question"), ("priority", "Priority"), ("status", "Status")], RED)
    row = _table(ws, row, "Claims", [
        {"claim": item[0], "status": item[1], "confidence": item[2], "evidence_refs": item[3]} if isinstance(item, list) else item
        for item in _as_list(export.get("claims"))
    ], [("claim", "Claim"), ("status", "Status"), ("confidence", "Confidence"), ("evidence_refs", "Evidence Refs")], PURPLE)
    _finish(ws, {"A": 46, "B": 18, "C": 18, "D": 38, "E": 24})

    ws = wb.create_sheet("Operations")
    row = _style_title(ws, "Operations", f"{reference} | gaps, collection, hunts, detection, actions", 6)
    row = _write_notice(ws, row, "Operational entries describe work to perform or validate. They are not automatic detection coverage.", 6)
    row = _table(ws, row, "Collection Requirements", _as_list(export.get("collection_requirements")), [
        ("question", "Question"),
        ("data_needed", "Data Needed"),
        ("priority", "Priority"),
        ("owner", "Owner"),
        ("status", "Status"),
    ], BLUE)
    row = _table(ws, row, "Hunt / Detection / Actions", _as_list(export.get("actions")), [
        ("type", "Type"),
        ("description", "Description"),
        ("status", "Status"),
        ("owner", "Owner"),
    ], ORANGE)
    _finish(ws, {"A": 42, "B": 44, "C": 18, "D": 18, "E": 18, "F": 20})

    ws = wb.create_sheet("History")
    row = _style_title(ws, "Local Audit History", f"{reference} | browser workspace history", 5)
    _table(ws, row, "History", _as_list(export.get("history")), [
        ("version", "Version"),
        ("timestamp", "Timestamp"),
        ("action", "Action"),
        ("description", "Description"),
        ("changed_fields", "Changed Fields"),
    ], GRAY)
    _finish(ws, {"A": 12, "B": 24, "C": 26, "D": 56, "E": 36})

    ws = wb.create_sheet("STIX Mapping")
    row = _style_title(ws, "STIX Mapping Notes", f"{reference} | semantic preservation", 4)
    _table(ws, row, "Export Loss Report", _as_list(export.get("stix_loss_report")), [
        ("semantic", "Internal Semantic"),
        ("mapping", "STIX Mapping"),
        ("handling", "Handling"),
    ], GRAY)
    _finish(ws, {"A": 30, "B": 44, "C": 58, "D": 18})

    ws = wb.create_sheet("Analyst Guardrails")
    row = _style_title(ws, "Analyst Guardrails", f"{reference} | interpretation rules", 4)
    _table(ws, row, "Rules", [
        {"rule": "Membership ≠ certainty", "meaning": "A member is associated with this profile based on the stated basis and evidence."},
        {"rule": "Recurrence ≠ corroboration", "meaning": "Cross-workspace recurrence does not prove maliciousness, ownership, attribution, or independent confirmation."},
        {"rule": "Shared infrastructure ≠ shared operator", "meaning": "Overlap may reflect hosting, reassignment, compromised infrastructure, or third-party services."},
        {"rule": "ATT&CK overlap ≠ attribution", "meaning": "Common techniques may be widely used and do not establish actor identity."},
        {"rule": "External attribution ≠ ODYSAFE attribution", "meaning": "External reporting remains separate unless ODYSAFE analysts adopt it."},
        {"rule": "Source count ≠ independent root count", "meaning": "Multiple publications may derive from the same original source."},
        {"rule": "Analytic confidence ≠ severity", "meaning": "Confidence reflects trust in the profile assessment, not impact, likelihood, or maliciousness."},
    ], [("rule", "Rule"), ("meaning", "Meaning")], ORANGE)
    _finish(ws, {"A": 36, "B": 78, "C": 18, "D": 18})

    stream = BytesIO()
    wb.save(stream)
    stream.seek(0)
    load_workbook(stream, read_only=True).close()
    stream.seek(0)
    return stream
