#!/usr/bin/env python3
# -- coding: utf-8 --
"""
forensic_report.py
forensic PDF
"""

import csv
import warnings
import argparse
import os
import sys
import traceback
import re
from fpdf import FPDF, XPos, YPos
from fpdf.errors import FPDFException
from email.utils import getaddresses

warnings.filterwarnings("ignore", category=UserWarning)
csv.field_size_limit(10_000_000)

# ---------- Config ----------
DEFAULT_FONT = "DejaVu"
DEFAULT_INPUT = "/home/kali/tool/csv/detection_results.csv"
DEFAULT_OUTPUT = "/home/kali/tool/forensic_report_final.pdf"
MAX_DEFAULT = None   # changed: None => process all emails by default
MAX_RECIPIENTS_TO_SHOW = 10

RISK_COLORS = {"High": (255,0,0), "Medium": (255,165,0), "Low": (0,128,0)}

RULE_WEIGHTS = {
    "Rule1": 20,
    "Rule2": 30,
    "Rule3": 25,
    "Rule4": 10,
    "Rule5": 15
}

REASON_TOKENS = {
    "link_mismatch": ("Link mismatch", "Links' href does not match displayed text."),
    "suspicious_words": ("Suspicious wording", "Contains phishing keywords."),
    "domain_lookalike": ("Domain lookalike", "Impersonation/typosquat domain."),
    "url_ip": ("URL uses IP", "Link contains raw IP address."),
    "suspicious_attachment": ("Suspicious attachment", "Attachment type indicates possible malware."),
}

# ---------- Helpers ----------
def sanitize_text(s):
    if s is None:
        return ""
    s = str(s)
    s = s.replace('\x00','')
    s = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f]','', s)
    return s

def soft_break_long_words(text, maxlen=50):
    parts = re.split(r'(\s+)', text)
    out = []
    for p in parts:
        if p.isspace() or len(p) <= maxlen:
            out.append(p)
        else:
            chunks = [p[i:i+maxlen] for i in range(0, len(p), maxlen)]
            out.append('\u200b'.join(chunks))
    return ''.join(out)

def ensure_space(pdf, needed):
    bottom_limit = pdf.h - pdf.b_margin
    if pdf.get_y() + needed > bottom_limit:
        pdf.add_page()
        try:
            pdf.set_x(pdf.l_margin)
        except Exception:
            pass

def safe_multi(pdf, text, h=6):
    s = sanitize_text(text)
    width = pdf.w - pdf.l_margin - pdf.r_margin

    if not s:
        try:
            pdf.multi_cell(width, h, "")
        except Exception:
            pass
        finally:
            try: pdf.set_x(pdf.l_margin)
            except Exception: pass
        return

    s2 = soft_break_long_words(s, maxlen=50)
    try:
        pdf.multi_cell(width, h, s2)
        pdf.set_x(pdf.l_margin)
        return
    except Exception:
        pass

    s3 = soft_break_long_words(s, maxlen=20)
    try:
        pdf.multi_cell(width, h, s3)
        pdf.set_x(pdf.l_margin)
        return
    except Exception:
        pass

    try:
        truncated = (s[:500] + " ... [truncated]") if len(s) > 500 else s
        pdf.multi_cell(width, h, truncated)
    except Exception:
        print("[Warning] Unable to render text; skipped.", file=sys.stderr)
    finally:
        try: pdf.set_x(pdf.l_margin)
        except Exception: pass

# ---------- Recipient parsing ----------
def parse_recipients_field(value):
    if not value:
        return []
    try:
        result = getaddresses([value])
        normalized = [(sanitize_text(name).strip(), sanitize_text(addr).strip()) for name, addr in result if addr or name]
        return normalized
    except Exception:
        parts = re.split(r'[;,]', sanitize_text(value))
        out = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            m = re.search(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})', p)
            addr = m.group(1) if m else ""
            name = p.replace(addr, "").strip().strip('"<>') if addr else p
            out.append((name, addr))
        return out

def find_all_possible_recipients(row):
    sources = ["To", "Recipients", "Delivered-To", "Envelope-To", "X-Original-To", "Cc", "Bcc"]
    found = []
    for s in sources:
        v = row.get(s)
        if v and str(v).strip():
            parsed = parse_recipients_field(v)
            for name, addr in parsed:
                found.append((name, addr, s))
    if not found:
        for k, v in row.items():
            try:
                if v and "@" in str(v):
                    parsed = parse_recipients_field(str(v))
                    for name, addr in parsed:
                        found.append((name, addr, k))
            except Exception:
                continue
    seen = set()
    unique = []
    for name, addr, source in found:
        key = (addr.lower() if addr else name.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append((name, addr, source))
    return unique

def format_recipient_list(recipients, max_show=MAX_RECIPIENTS_TO_SHOW):
    count = len(recipients)
    lines = []
    for i, (name, addr, source) in enumerate(recipients[:max_show], start=1):
        display = name if name else "(no display name)"
        addr_display = addr if addr else "(no address)"
        lines.append(f"{i}. {display} <{addr_display}>  [source: {source}]")
    if count > max_show:
        lines.append(f"... and {count - max_show} more recipients")
    summary = f"{count} recipient(s) found"
    return count, summary, lines

# ---------- PDF class ----------
class PDFReport(FPDF):
    def _init_(self, font_paths=None):
        super()._init_()
        self.set_left_margin(20)
        self.set_right_margin(20)
        self.set_auto_page_break(auto=False)
        font_paths = font_paths or {}
        def try_add(name, style, path):
            try:
                if path and os.path.isfile(path):
                    self.add_font(name, style, path)
                    return True
            except Exception as e:
                print("[FontError]", path, e, file=sys.stderr)
            return False
        added = 0
        if try_add(DEFAULT_FONT, "", font_paths.get('regular') or "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
            added += 1
        if try_add(DEFAULT_FONT, "B", font_paths.get('bold') or "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
            added += 1
        if added == 0:
            try_add(DEFAULT_FONT, "", "C:\\Windows\\Fonts\\DejaVuSans.ttf")
            try_add(DEFAULT_FONT, "B", "C:\\Windows\\Fonts\\DejaVuSans-Bold.ttf")
        self.add_page()

    def header(self):
        title = "Forensic Email Report — Phishing Probability & Reasons"
        width = self.w - self.l_margin - self.r_margin
        self.set_font(DEFAULT_FONT, "B", 14)
        self.set_x(self.l_margin)
        self.cell(width, 10, title, border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        width = self.w - self.l_margin - self.r_margin
        self.set_font(DEFAULT_FONT, "", 8)
        self.set_x(self.l_margin)
        self.cell(width, 10, f"Page {self.page_no()}", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP)

# ---------- Rule explainers ----------
def explain_rule1(row):
    s = (row.get("Rule1_Status") or "").strip()
    if not s:
        return False, "Rule1: no data", "No Rule1 data available."
    up = s.upper()
    if up in ("DIFFER","SPOOF","MISMATCH","SUSPICIOUS"):
        return True, "Sender spoofing / mismatch", f'Rule1 value: "{s}". Display name differs from From address (possible impersonation).'
    return False, f"Rule1: {s}", f'Rule1 value: "{s}".'

def explain_rule2(row):
    r = (row.get("Rule2_Result") or row.get("Rule2","")).strip()
    if not r:
        return False, "Rule2: no data", "No Rule2 data available."
    up = r.upper()
    if "PHISH" in up or "SUSPIC" in up or "MALIC" in up:
        return True, "Message content suspicious", f'Rule2 value: "{r}". Message body/links/attachments matched phishing patterns.'
    return False, f"Rule2: {r}", f'Rule2 value: "{r}".'

def explain_rule3(row):
    lvl = (row.get("Rule3_Risk_Level") or "").strip()
    if not lvl:
        return False, "Rule3: no data", "No Rule3 data available."
    lvlc = lvl.capitalize()
    if lvlc in ("High","Medium"):
        return True, f"High risk ({lvlc})", f"Rule3 risk level: {lvl}. Aggregated indicators."
    return False, f"Low risk ({lvlc})", f"Rule3: {lvl}."

def explain_rule4(row):
    r4 = (row.get("Rule4") or row.get("Rule4_Result") or row.get("Rule4_Status") or "").strip()
    if not r4:
        return False, "Rule4: SAFE (no data)", "Rule4 field missing or empty in CSV; treated as SAFE (no evidence)."
    up = r4.upper()
    if any(k in up for k in ("PHISH","SUSP","MALIC")):
        return True, "Rule4 suspicious", f'Rule4 value: "{r4}".'
    return False, f"Rule4: {r4}", f'Rule4 value: "{r4}".'

def explain_rule5(row):
    flag = row.get("Rule5_Phishing")
    raw = (row.get("Rule5_Reasons") or "").strip()
    items = []
    if raw:
        tokens = []
        for sep in ["|",",",";"]:
            if sep in raw:
                tokens = [p.strip() for p in raw.split(sep) if p.strip()]
                break
        if not tokens:
            tokens = raw.split()
        for t in tokens:
            mapping = REASON_TOKENS.get(t)
            if mapping:
                items.append(f"{mapping[0]} ({t})")
            else:
                items.append(f"{t}")
    flagv = str(flag).strip().lower() if flag is not None else ""
    if not items and flagv in ("true","1","yes"):
        items.append("Rule5 flagged phishing (no tokens provided)")
    if items:
        return True, "Rule5 indicators present", "Indicators: " + ", ".join(items)
    return False, "Rule5: no indicators", "No Rule5 indicators found."

# ---------- Scoring ----------
def compute_phishing_score(rules_eval, weights=RULE_WEIGHTS):
    total = 0
    max_total = sum(weights.get(rule, 0) for rule,,,_ in rules_eval)
    contributing = []
    safe = []
    for rule, triggered, short, detail in rules_eval:
        w = weights.get(rule, 0)
        if triggered:
            total += w
            contributing.append(rule)
        else:
            safe.append(rule)
    score_pct = int(round((total / max_total) * 100)) if max_total > 0 else 0
    return score_pct, contributing, safe

# ---------- Narrative ----------
def build_full_narrative(rules_list):
    pieces = []
    triggered_any = False
    for rule, triggered, short, detail in rules_list:
        if triggered:
            triggered_any = True
            pieces.append(f"{rule} triggered: {detail}")
    if not triggered_any:
        return "No significant phishing indicators were detected in the available fields."
    narrative = ("This email has been identified as phishing. " +
                 " ".join(pieces) +
                 " Based on the combination of the above signals, the message demonstrates strong characteristics of a phishing attack.")
    return narrative

# ---------- Render per-email forensic page ----------
def render_email_forensic(pdf, row, idx):
    filename = row.get("Filename","")
    sender = row.get("From","")
    subject_raw = row.get("Subject","")
    if not subject_raw:
        subject_raw = row.get("Subjec", "") or "(empty or missing)"
    subject_raw = sanitize_text(subject_raw)

    date_raw = row.get("Date","")
    risk = (row.get("Rule3_Risk_Level") or "Low").strip()
    color = RISK_COLORS.get(risk, (0,0,0))

    recipients = find_all_possible_recipients(row)
    rcpt_count, rcpt_summary, rcpt_lines = format_recipient_list(recipients, max_show=MAX_RECIPIENTS_TO_SHOW)

    ensure_space(pdf, 60)
    width = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font(DEFAULT_FONT, "B", 13)
    pdf.set_text_color(*color)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 8, f"Email #{idx}: {filename}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_text_color(0,0,0)
    pdf.set_font(DEFAULT_FONT, "", 11)
    safe_multi(pdf, f"From: {sender}")
    safe_multi(pdf, f"To (summary): {rcpt_summary}")
    for line in rcpt_lines:
        safe_multi(pdf, f"  {line}")
    if rcpt_count == 0:
        raw_to = row.get("To") or ""
        if raw_to:
            safe_multi(pdf, f"To (raw): {raw_to}")
        else:
            safe_multi(pdf, "To (raw): (empty)")
    safe_multi(pdf, f"Date: {date_raw}")
    safe_multi(pdf, f"Subject: {subject_raw}")
    safe_multi(pdf, f"Risk Level: {risk}")
    pdf.ln(8)

    r1_t, r1_s, r1_d = explain_rule1(row)
    r2_t, r2_s, r2_d = explain_rule2(row)
    r3_t, r3_s, r3_d = explain_rule3(row)
    r4_t, r4_s, r4_d = explain_rule4(row)
    r5_t, r5_s, r5_d = explain_rule5(row)
    rules = [("Rule1", r1_t, r1_s, r1_d), ("Rule2", r2_t, r2_s, r2_d),
             ("Rule3", r3_t, r3_s, r3_d), ("Rule4", r4_t, r4_s, r4_d),
             ("Rule5", r5_t, r5_s, r5_d)]

    score_pct, contributing, safe_rules = compute_phishing_score(rules)

    pdf.set_font(DEFAULT_FONT, "B", 12)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 7, f"Phishing probability: {score_pct}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(DEFAULT_FONT, "", 11)
    if contributing:
        safe_multi(pdf, "Rules that caused phishing: " + ", ".join(contributing))
    else:
        safe_multi(pdf, "Rules that caused phishing: None")
    if safe_rules:
        safe_multi(pdf, "Rules marked SAFE: " + ", ".join(safe_rules))
    pdf.ln(8)

    narrative = build_full_narrative(rules)
    pdf.set_font(DEFAULT_FONT, "B", 11)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 7, "Why this email is classified as phishing", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(DEFAULT_FONT, "", 11)
    safe_multi(pdf, narrative)
    pdf.ln(8)

    pdf.set_font(DEFAULT_FONT, "B", 11)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 7, "Per-rule details", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(DEFAULT_FONT, "", 10)
    for rule, triggered, short, detail in rules:
        tag = "TRIGGERED" if triggered else "SAFE"
        safe_multi(pdf, f"- {rule} [{tag}]: {short}")
        safe_multi(pdf, f"  Detail: {detail}")
        pdf.ln(1)
    pdf.ln(8)

    ensure_space(pdf, 60)
    y = pdf.get_y()
    pdf.set_draw_color(200,200,200)
    pdf.set_x(pdf.l_margin)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(4)

    ensure_space(pdf, 120)
    pdf.set_font(DEFAULT_FONT, "B", 11)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 7, "Evidence (selected fields)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(DEFAULT_FONT, "", 10)
    ev = [
        ("Filename", row.get("Filename","")),
        ("From", row.get("From","")),
        ("To (raw)", row.get("To","") or "(empty)"),
        ("Extracted recipients (count)", str(rcpt_count)),
        ("Date", row.get("Date","")),
        ("Subject", subject_raw),
        ("Rule1_Status", row.get("Rule1_Status","")),
        ("Rule2_Result", row.get("Rule2_Result","")),
        ("Rule3_Risk_Level", row.get("Rule3_Risk_Level","")),
        ("Rule4", row.get("Rule4") or row.get("Rule4_Result") or row.get("Rule4_Status") or "(no data)"),
        ("Rule5_Phishing", row.get("Rule5_Phishing","")),
        ("Rule5_Reasons", row.get("Rule5_Reasons","(not provided)"))
    ]
    raw = row.get("Raw_Headers") or row.get("Headers") or ""
    if raw:
        ev.append(("Raw_Headers", raw[:1000] + ("..." if len(raw)>1000 else "")))
    for k,v in ev:
        safe_multi(pdf, f"- {k}: {v}")
    pdf.ln(8)

    ensure_space(pdf, 40)
    y = pdf.get_y()
    pdf.set_draw_color(200,200,200)
    pdf.set_x(pdf.l_margin)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(4)

    ensure_space(pdf, 60)
    pdf.set_font(DEFAULT_FONT, "B", 11)
    pdf.set_x(pdf.l_margin)
    pdf.cell(width, 7, "Recommendations / Actions", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(DEFAULT_FONT, "", 10)
    recs = []
    if "Rule1" in contributing:
        recs.append("Block or monitor the sender address/domain; search SIEM for similar messages.")
    if "Rule2" in contributing or "Rule5" in contributing:
        recs.append("Do NOT click links. Extract URLs and analyze in sandbox/URL scanners.")
    if "Rule3" in contributing:
        recs.append("Quarantine the message and consider IR steps due to high risk.")
    if rcpt_count > 0:
        recs.append("Notify recipients (if internal) and check if any users interacted with the message.")
    recs.append("Extract IOCs and update blocklists; preserve original EML and headers for analysis.")
    for r in recs:
        safe_multi(pdf, f"- {r}")
    pdf.ln(10)

# ---------- Main CSV -> PDF ----------
def csv_to_pdf_forensic(input_csv, output_pdf, font_paths=None, max_emails=MAX_DEFAULT):
    if not os.path.isfile(input_csv):
        raise FileNotFoundError("CSV not found: " + input_csv)
    pdf = PDFReport(font_paths)
    pdf.set_font(DEFAULT_FONT, "", 12)
    with open(input_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV missing header row.")
        for idx, row in enumerate(reader, start=1):
            # only enforce limit if max_emails is not None
            if (max_emails is not None) and (idx > max_emails):
                break
            try:
                render_email_forensic(pdf, row, idx)
            except Exception:
                print(f"[Error] rendering row #{idx}", file=sys.stderr)
                traceback.print_exc()
                continue
    outdir = os.path.dirname(output_pdf)
    if outdir and not os.path.isdir(outdir):
        os.makedirs(outdir, exist_ok=True)
    pdf.output(output_pdf)
    print("✔ Forensic PDF created:", output_pdf)

# ---------- CLI ----------
def parse_args(default_in, default_out):
    p = argparse.ArgumentParser(description="Forensic email PDF report — final")
    p.add_argument("input_csv", nargs="?", default=default_in)
    p.add_argument("output_pdf", nargs="?", default=default_out)
    p.add_argument("--font-regular")
    p.add_argument("--font-bold")
    p.add_argument("--max", type=int, default=None, help="Max emails to process (default: all)")
    p.add_argument("--max-recipients", type=int, default=MAX_RECIPIENTS_TO_SHOW, help="Max recipients to show per email")
    return p.parse_args()

if _name_ == "_main_":
    args = parse_args(DEFAULT_INPUT, DEFAULT_OUTPUT)
    try:
        MAX_RECIPIENTS_TO_SHOW = int(args.max_recipients)
    except Exception:
        pass
    font_paths = {"regular": args.font_regular, "bold": args.font_bold}
    try:
        csv_to_pdf_forensic(args.input_csv, args.output_pdf, font_paths=font_paths, max_emails=args.max)
    except Exception as e:
        print("✖ Failed:", e, file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
