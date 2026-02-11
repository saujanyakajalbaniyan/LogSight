from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from collections import Counter, defaultdict
import re

LOG_FILE = Path("../logs/errors.log")
app = FastAPI()

class Query(BaseModel):
    pattern: str

@app.get("/summary")
def summary():
    if not LOG_FILE.exists():
        return {"status":"no_logs"}
    total = 0
    counts = Counter()
    with LOG_FILE.open("r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            total += 1
            msg = re.sub(r"\d{4}-\d{2}-\d{2}.*?\s","",ln)
            msg = re.sub(r"\s+"," ",msg).strip()[:120]
            counts[msg] += 1
    return {"total_lines":total, "top5":counts.most_common(5)}

@app.post("/search_fast")
def search_fast(q: Query):
    if not LOG_FILE.exists():
        return {"matches":0, "lines":[]}
    matches = []
    total_matches = 0
    prog = re.compile(q.pattern, re.IGNORECASE)
    with LOG_FILE.open("r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            if prog.search(ln):
                total_matches += 1
                if len(matches) < 200:
                    matches.append(ln.strip())
    return {"matches":total_matches, "lines":matches}

@app.post("/search")
def search(q: Query):
    return search_fast(q)

@app.get("/detect_bruteforce")
def detect_bruteforce(min_attempts: int = 20):
    if not LOG_FILE.exists():
        return {}
    ip_counts = defaultdict(int)
    with LOG_FILE.open("r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            if re.search(r"failed password|authentication failure|invalid user",ln,re.IGNORECASE):
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ln)
                if m:
                    ip_counts[m.group(1)] += 1
    attackers = {ip:c for ip,c in ip_counts.items() if c >= min_attempts}
    return {"threshold":min_attempts, "attackers":attackers}

@app.get("/top_ips")
def top_ips(limit: int = 20):
    if not LOG_FILE.exists():
        return {"top_ips":[]}
    c = Counter()
    with LOG_FILE.open("r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            for m in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", ln):
                c[m] += 1
    return {"top_ips":c.most_common(limit)}

@app.get("/alerts")
def alerts():
    if not LOG_FILE.exists():
        return {"alerts":[]}
    total = 0
    errs = 0
    with LOG_FILE.open("r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            total += 1
            if re.search(r"error|fail|denied|panic|crash", ln, re.IGNORECASE):
                errs += 1
    rate = errs / max(total, 1)
    out = []
    if rate > 0.05:
        out.append({"type":"high_error_rate","rate":rate,"errors":errs,"total":total})
    return {"alerts":out, "error_rate":rate, "errors":errs, "total":total}

