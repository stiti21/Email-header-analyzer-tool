#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv, warnings, argparse, os, sys, re, logging, json
from fpdf import FPDF, XPos, YPos
from email.utils import getaddresses

# Optional OpenAI
try:
    import openai
except Exception:
    openai = None

warnings.filterwarnings("ignore", category=UserWarning)
csv.field_size_limit(10_000_000)

DEFAULT_FONT_NAME = "DejaVu"
FALLBACK_FONT = "Helvetica"
DEFAULT_INPUT = "/home/kali/tool/csv/detection_results.csv"
DEFAULT_OUTPUT = "/home/kali/tool/forensic_report_final_ai.pdf"
MAX_DEFAULT = None
MAX_RECIPIENTS_TO_SHOW = 10

RISK_COLORS = {"High": (255, 0, 0), "Medium": (255, 165, 0), "Low": (0, 128, 0)}
RULE_WEIGHTS = {"Rule1": 20, "Rule2": 30, "Rule3": 25, "Rule4": 10, "Rule5": 15}

# ---------- Emoji regex only (no EMOJI_MAP) ----------
EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FA6F"
    "\u2600-\u26FF"
    "\u2700-\u27BF"
    "]+",
    flags=re.UNICODE,
)

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\uFEFF\u2060]")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------- Sanitizers ----------
def replace_known_emojis(text):
    if not text:
        return text
    # استبدال أي إيموجي بالتوكن العام [EMOJI]
    return EMOJI_RE.sub("[EMOJI]", text)

def strip_nonprintables(text):
    if not text:
        return text
    text = text.replace("\x00", "")
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = ZERO_WIDTH_RE.sub("", text)
    return text

def sanitize_text(s):
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\t", "    ")
    s = strip_nonprintables(s)
    s = replace_known_emojis(s)
    return s

def normalize_fallback(s):
    if not s:
        return ""
    s = sanitize_text(s)
    s = ZERO_WIDTH_RE.sub("", s)
    return "".join(ch if ord(ch) <= 255 else "?" for ch in s)

def soft_break(text, limit=50, use_zwsp=True):
    if not text:
        return ""
    parts = re.split(r"(\s+)", text)
    out = []
    for p in parts:
        if p.isspace() or len(p) <= limit:
            out.append(p)
        else:
            chunks = [p[i:i+limit] for i in range(0, len(p), limit)]
            out.append(("\u200b" if use_zwsp else " ").join(chunks))
    return "".join(out)

def ensure_space(pdf, needed):
    try:
        if pdf.get_y() + needed > pdf.h - pdf.b_margin:
            pdf.add_page()
            pdf.set_x(pdf.l_margin)
    except Exception:
        pdf.add_page()

# ---------- PDF class ----------
class PDFReport(FPDF):
    def __init__(self, font_paths=None):
        super().__init__()
        self.set_left_margin(20)
        self.set_right_margin(20)
        self.set_auto_page_break(False)
        self.unicode_font = None

        paths = font_paths or {}

        def try_add(preg, pbold):
            ok = False
            try:
                if preg and os.path.isfile(preg):
                    self.add_font(DEFAULT_FONT_NAME, "", preg)
                    ok = True
                if pbold and os.path.isfile(pbold):
                    self.add_font(DEFAULT_FONT_NAME, "B", pbold)
                    ok = True
            except Exception:
                ok = False
            return ok

        if try_add(paths.get("regular"), paths.get("bold")):
            self.unicode_font = DEFAULT_FONT_NAME
        else:
            if try_add(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            ):
                self.unicode_font = DEFAULT_FONT_NAME

        try:
            self.set_font(self.unicode_font or FALLBACK_FONT, "", 12)
        except Exception:
            self.set_font(FALLBACK_FONT, "", 12)

        self.add_page()

    def header(self):
        title = "Forensic Email Report — Phishing Probability & Reasons"
        t = title if self.unicode_font else normalize_fallback(title)
        try:
            self.set_font(self.unicode_font or FALLBACK_FONT, "B", 14)
        except Exception:
            self.set_font(FALLBACK_FONT, "B", 14)
        width = self.w - self.l_margin - self.r_margin
        self.cell(
            width,
            10,
            t,
            border=0,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        try:
            self.set_font(self.unicode_font or FALLBACK_FONT, "", 8)
        except Exception:
            self.set_font(FALLBACK_FONT, "", 8)
        self.cell(
            self.w - self.l_margin - self.r_margin,
            10,
            f"Page {self.page_no()}",
            border=0,
            new_x=XPos.RIGHT,
            new_y=YPos.TOP,
        )

# ---------- Safe write ----------
def safe_multi(pdf, text, h=6):
    if text is None:
        text = ""
    s = sanitize_text(text)
    use_uni = pdf.unicode_font is not None
    s = soft_break(s, 50, use_zwsp=use_uni)
    if not use_uni:
        s = normalize_fallback(s)

    width = pdf.w - pdf.l_margin - pdf.r_margin
    try:
        pdf.multi_cell(width, h, s)
    except Exception:
        try:
            pdf.multi_cell(width, h, normalize_fallback(s[:400]) + "...")
        except Exception:
            pdf.multi_cell(width, h, "")
    pdf.set_x(pdf.l_margin)

# ---------- Recipients ----------
def parse_recipients_field(value):
    if not value:
        return []
    try:
        result = getaddresses([value])
        return [(sanitize_text(n).strip(), sanitize_text(a).strip()) for n, a in result if a or n]
    except Exception:
        out = []
        parts = re.split(r"[;,]", sanitize_text(value))
        for p in parts:
            p = p.strip()
            if not p:
                continue
            m = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", p)
            addr = m.group(0) if m else ""
            name = p.replace(addr, "").strip().strip('"<>') if addr else p
            out.append((name, addr))
        return out

def find_all_possible_recipients(row):
    sources = ["To","Recipients","Delivered-To","Envelope-To","X-Original-To","Cc","Bcc"]
    found = []
    for s in sources:
        v = row.get(s)
        if v and str(v).strip():
            for name, addr in parse_recipients_field(v):
                found.append((name, addr, s))
    if not found:
        for k, v in row.items():
            if v and "@" in str(v):
                for name, addr in parse_recipients_field(v):
                    found.append((name, addr, k))
    unique = []
    seen = set()
    for name, addr, src in found:
        key = addr.lower() if addr else name.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append((name, addr, src))
    return unique

def format_recipient_list(rec, max_show=MAX_RECIPIENTS_TO_SHOW):
    count = len(rec)
    lines = []
    for i, (name, addr, src) in enumerate(rec[:max_show], 1):
        lines.append(f"{i}. {name or '(no display name)'} <{addr or '(no address)'}> [source: {src}]")
    if count > max_show:
        lines.append(f"... and {count - max_show} more recipients")
    return count, f"{count} recipient(s) found", lines

# ---------- Rule explainers ----------
def explain_rule1(row):
    s = (row.get("Rule1_Status") or "").strip()
    if not s:
        return False, "Rule1: no data", "No Rule1 data available."
    up = s.upper()
    if up in ("DIFFER", "SPOOF", "MISMATCH", "SUSPICIOUS"):
        return True, "Sender spoofing / mismatch", f'Rule1: "{s}".'
    return False, f"Rule1: {s}", f'Rule1: "{s}".'

def explain_rule2(row):
    r = (row.get("Rule2_Result") or row.get("Rule2","")).strip()
    if not r:
        return False, "Rule2: no data", "No Rule2 data available."
    up = r.upper()
    if any(x in up for x in ("PHISH","SUSP","MALIC")):
        return True, "Message content suspicious", f'Rule2: "{r}".'
    return False, f"Rule2: {r}", f'Rule2: "{r}".'

def explain_rule3(row):
    lvl = (row.get("Rule3_Risk_Level") or "").strip()
    if not lvl:
        return False, "Rule3: no data", "No Rule3 data available."
    if lvl.capitalize() in ("High","Medium"):
        return True, f"High risk ({lvl})", f"Rule3: {lvl}."
    return False, f"Rule3: {lvl}", f"Rule3: {lvl}."

def explain_rule4(row):
    r = (row.get("Rule4") or row.get("Rule4_Result") or row.get("Rule4_Status") or "").strip()
    if not r:
        return False, "Rule4: SAFE (no data)", "Rule4 missing."
    up = r.upper()
    if any(x in up for x in ("PHISH","SUSP","MALIC")):
        return True, "Rule4 suspicious", f'Rule4: "{r}".'
    return False, f"Rule4: {r}", f'Rule4: "{r}".'

def explain_rule5(row):
    flag = (row.get("Rule5_Phishing") or "").lower()
    raw = (row.get("Rule5_Reasons") or "").strip()
    items = []
    if raw:
        for sep in ("|",",",";"):
            if sep in raw:
                items = [p.strip() for p in raw.split(sep) if p.strip()]
                break
        if not items:
            items = raw.split()
    if items or flag in ("true","1","yes"):
        return True, "Rule5 indicators present", "Indicators: " + ", ".join(items or ["flagged"])
    return False, "Rule5: no indicators", "No Rule5 indicators."

# ---------- Scoring ----------
def compute_phishing_score(rules_eval, weights=RULE_WEIGHTS):
    total = 0
    max_total = sum(weights.get(r,0) for r,_,_,_ in rules_eval)
    contributing = []
    safe = []
    for rule, trig, short, detail in rules_eval:
        w = weights.get(rule,0)
        if trig:
            total += w
            contributing.append(rule)
        else:
            safe.append(rule)
    pct = int(round(total/max_total*100)) if max_total else 0
    return pct, contributing, safe

def build_full_narrative(rules_list):
    parts = [
        f"{r} triggered: {d}"
        for r, t, s, d in rules_list if t
    ]
    if not parts:
        return "No significant phishing indicators detected in the available fields."
    return (
        "This email has been identified as phishing. "
        + " ".join(parts)
        + " Based on these indicators, the email shows strong phishing characteristics."
    )

# ---------- AI integration ----------
def ai_analyze_row(row, model="gpt-4o-mini", timeout=10):
    if openai is None:
        return None
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None

    context = {
        "from": sanitize_text(row.get("From","")),
        "to": sanitize_text(row.get("To","")),
        "cc": sanitize_text(row.get("Cc","")),
        "subject": sanitize_text(row.get("Subject","") or row.get("Subjec","")),
        "date": sanitize_text(row.get("Date","")),
        "headers_snippet": (row.get("Raw_Headers") or row.get("Headers") or "")[:2000],
        "rule_fields": {
            k: (row.get(k) or "")
            for k in ["Rule1_Status","Rule2_Result","Rule3_Risk_Level","Rule4","Rule5_Phishing","Rule5_Reasons"]
        },
    }

    prompt = (
        "You are a concise email-forensics assistant. "
        "Return ONLY JSON with keys: ai_score (0-100), ai_reasons, ai_narrative, ai_actions.\n"
        "Context:\n" + json.dumps(context, ensure_ascii=False)
    )

    try:
        openai.api_key = key
        resp = openai.ChatCompletion.create(
            model=model,
            temperature=0,
            max_tokens=500,
            request_timeout=timeout,
            messages=[{"role":"user","content":prompt}],
        )
        txt = resp.choices[0].message.content.strip()
        txt = txt[txt.find("{"):]
        data = json.loads(txt)
        data["ai_score"] = int(round(float(data["ai_score"])))
        return data
    except Exception as e:
        logger.warning("AI analysis failed: %s", e)
        return None

# ---------- Render PDF ----------
def render_email_forensic(pdf, row, idx, ai_result=None):
    filename = row.get("Filename","")
    sender = row.get("From","")
    subject_raw = sanitize_text(row.get("Subject","") or row.get("Subjec","") or "(empty)")
    date_raw = row.get("Date","")
    risk = (row.get("Rule3_Risk_Level") or "Low").strip()
    color = RISK_COLORS.get(risk,(0,0,0))

    rec = find_all_possible_recipients(row)
    rcpt_count, rcpt_summary, rcpt_lines = format_recipient_list(rec)

    ensure_space(pdf,60)
    width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",13)
    pdf.set_text_color(*color)
    pdf.cell(
        width,
        8,
        f"Email #{idx}: {filename}",
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_text_color(0,0,0)

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",11)
    safe_multi(pdf,f"From: {sender}")
    safe_multi(pdf,f"To (summary): {rcpt_summary}")
    for line in rcpt_lines:
        safe_multi(pdf,"  "+line)
    if rcpt_count==0:
        safe_multi(pdf,"To (raw): "+(row.get("To") or "(empty)"))
    safe_multi(pdf,f"Date: {date_raw}")
    safe_multi(pdf,f"Subject: {subject_raw}")
    safe_multi(pdf,f"Risk Level: {risk}")
    pdf.ln(8)

    r1 = explain_rule1(row)
    r2 = explain_rule2(row)
    r3 = explain_rule3(row)
    r4 = explain_rule4(row)
    r5 = explain_rule5(row)

    rules_eval = [
        ("Rule1",*r1),
        ("Rule2",*r2),
        ("Rule3",*r3),
        ("Rule4",*r4),
        ("Rule5",*r5),
    ]

    score, contributing, safe_rules = compute_phishing_score(rules_eval)
    ai_score = ai_result.get("ai_score") if ai_result else None

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",12)
    line = f"Phishing probability: {score}%"
    if ai_score is not None:
        line += f"   [AI: {ai_score}%]"
    pdf.cell(
        width,
        7,
        line,
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",11)
    safe_multi(pdf,"Rules that caused phishing: "+(", ".join(contributing) if contributing else "None"))
    if safe_rules:
        safe_multi(pdf,"Rules marked SAFE: "+", ".join(safe_rules))
    pdf.ln(8)

    narrative = ai_result.get("ai_narrative") if (ai_result and ai_result.get("ai_narrative")) else build_full_narrative(rules_eval)

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",11)
    pdf.cell(
        width,
        7,
        "Why this email is classified as phishing",
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",11)
    safe_multi(pdf,narrative)
    pdf.ln(8)

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",11)
    pdf.cell(
        width,
        7,
        "Per-rule details",
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",10)
    for r,t,s,d in rules_eval:
        safe_multi(pdf,f"- {r} [{'TRIGGERED' if t else 'SAFE'}]: {s}")
        safe_multi(pdf,f"  Detail: {d}")
        pdf.ln(1)
    pdf.ln(8)

    ensure_space(pdf,60)
    y=pdf.get_y()
    pdf.set_draw_color(200,200,200)
    pdf.line(pdf.l_margin,y,pdf.w-pdf.r_margin,y)
    pdf.ln(4)

    ensure_space(pdf,120)
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",11)
    pdf.cell(
        width,
        7,
        "Evidence (selected fields)",
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",10)

    ev = [
        ("Filename",row.get("Filename","")),
        ("From",row.get("From","")),
        ("To (raw)",row.get("To","") or "(empty)"),
        ("Extracted recipients",rcpt_count),
        ("Date",date_raw),
        ("Subject",subject_raw),
        ("Rule1_Status",row.get("Rule1_Status","")),
        ("Rule2_Result",row.get("Rule2_Result","")),
        ("Rule3_Risk_Level",row.get("Rule3_Risk_Level","")),
        ("Rule4",row.get("Rule4") or row.get("Rule4_Result") or row.get("Rule4_Status") or "(no data)"),
        ("Rule5_Phishing",row.get("Rule5_Phishing","")),
        ("Rule5_Reasons",row.get("Rule5_Reasons","")),
    ]

    rh = row.get("Raw_Headers") or row.get("Headers") or ""
    if rh:
        ev.append(("Raw_Headers",rh[:1000]+("..." if len(rh)>1000 else "")))

    if ai_result:
        ev.append(("AI_Score",ai_result.get("ai_score","")))
        ev.append(("AI_Reasons",json.dumps(ai_result.get("ai_reasons",""),ensure_ascii=False)))
        ev.append(("AI_Actions",json.dumps(ai_result.get("ai_actions",""),ensure_ascii=False)))

    for k,v in ev:
        safe_multi(pdf,f"- {k}: {v}")
    pdf.ln(8)

    ensure_space(pdf,40)
    y=pdf.get_y()
    pdf.line(pdf.l_margin,y,pdf.w-pdf.r_margin,y)
    pdf.ln(4)

    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"B",11)
    pdf.cell(
        width,
        7,
        "Recommendations / Actions",
        border=0,
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_font(pdf.unicode_font or FALLBACK_FONT,"",10)
    recs = []
    if "Rule1" in contributing:
        recs.append("Block sender domain; check SIEM.")
    if "Rule2" in contributing or "Rule5" in contributing:
        recs.append("Do NOT click links; analyze URLs in sandbox.")
    if "Rule3" in contributing:
        recs.append("Quarantine message; escalate to IR team.")
    if rcpt_count:
        recs.append("Notify internal recipients; check for interaction.")
    if ai_result:
        for a in ai_result.get("ai_actions",[]):
            recs.append(f"[AI] {a}")
    recs.append("Extract IOCs; update blocklists; preserve original EML.")

    for r in recs:
        safe_multi(pdf,"- "+r)

    pdf.ln(10)

# ---------- Main ----------
def csv_to_pdf_forensic(input_csv, output_pdf, font_paths=None, max_emails=MAX_DEFAULT, enable_ai=False, ai_model="gpt-4o-mini", ai_timeout=10):
    if not os.path.isfile(input_csv):
        raise FileNotFoundError("CSV not found: "+input_csv)

    pdf = PDFReport(font_paths)
    with open(input_csv,"r",encoding="utf-8-sig",errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV missing header row")

        for idx,row in enumerate(reader,1):
            if max_emails and idx>max_emails:
                break
            try:
                ai_result = ai_analyze_row(row,ai_model,ai_timeout) if enable_ai else None
                render_email_forensic(pdf,row,idx,ai_result)
            except Exception:
                logger.exception("Error rendering row %d",idx)
                continue

    os.makedirs(os.path.dirname(output_pdf) or ".",exist_ok=True)
    pdf.output(output_pdf)
    logger.info("✔ Forensic PDF created: %s",output_pdf)

def parse_args():
    p = argparse.ArgumentParser(description="Forensic email PDF report — AI-enhanced")
    p.add_argument("input_csv", nargs="?", default=DEFAULT_INPUT)
    p.add_argument("output_pdf", nargs="?", default=DEFAULT_OUTPUT)
    p.add_argument("--font-regular")
    p.add_argument("--font-bold")
    p.add_argument("--max",type=int,default=None)
    p.add_argument("--max-recipients",type=int,default=MAX_RECIPIENTS_TO_SHOW)
    p.add_argument("--quiet",action="store_true")
    p.add_argument("--ai",action="store_true")
    p.add_argument("--ai-model",default="gpt-4o-mini")
    p.add_argument("--ai-timeout",type=int,default=10)
    return p.parse_args()

if __name__=="__main__":
    args = parse_args()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    MAX_RECIPIENTS_TO_SHOW = args.max_recipients

    fonts = {"regular":args.font_regular,"bold":args.font_bold}
    try:
        csv_to_pdf_forensic(
            args.input_csv,
            args.output_pdf,
            fonts,
            max_emails=args.max,
            enable_ai=args.ai,
            ai_model=args.ai_model,
            ai_timeout=args.ai_timeout
        )
    except Exception as e:
        logger.exception("✖ Failed: %s",e)
        sys.exit(1)
