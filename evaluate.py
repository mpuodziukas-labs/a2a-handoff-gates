"""Run every planted case through planner, gate, executor and trace verifier.
Prints one row per class, the success count, median latency and the corpus hash. Exit 1 on any mismatch."""
import hashlib
import json
import pathlib
import statistics
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone

from executor import Executor
from planner import GENESIS, HandoffReceipt, build_task, link, load_key, sign_handoff
from verify_trace import verify_trace

HERE = pathlib.Path(__file__).parent
CLASSES = ["CLEAN", "UNSIGNED", "TAMPERED", "REPLAYED", "EXPIRED", "TOOL_NOT_ALLOWED",
           "ARG_OUT_OF_SCHEMA", "BUDGET_EXCEEDED", "TRACE_SPLICED"]


def rechain(trace):
    """Recompute prev_hash and hash for every record, as an attacker who can write the whole trace would."""
    prev = GENESIS
    for rec in trace:
        rec["prev_hash"] = prev
        rec["hash"] = link(prev, {k: v for k, v in rec.items() if k != "hash"})
        prev = rec["hash"]
    return trace


def apply_splice(trace, final, spec):
    t = [dict(r) for r in trace]
    kind = spec["kind"]
    if kind == "swap":
        t[spec["index"]][spec["field"]] = spec["value"]
    elif kind == "insert":
        t.insert(spec["index"], dict(spec["record"]))
    elif kind == "drop":
        t.pop(spec["index"])
    elif kind == "final":
        final = {"key": "total", "value": spec["value"]}
    return (rechain(t) if spec.get("rechain") else t), final


def run_case(case, key):
    """Returns (outcome, reason) for one case."""
    t = case["task"]
    task = build_task(t["id"], t["goal"], t["allowed_tools"], t["max_calls"], t["deadline"])
    nonce = "n-" + case["id"]
    sign = case.get("sign", "ok")
    receipt = None if sign == "none" else HandoffReceipt(nonce, "") if sign == "empty" else sign_handoff(key, task, nonce)
    delivered = replace(task, **case["tamper"]) if "tamper" in case else task
    ex = Executor(key)
    reason = ex.accept(delivered, receipt, case["now"])
    if case.get("replay") and reason == "OK":
        if case["replay"] == "reuse_nonce":  # a different task signed under the same nonce
            delivered = replace(task, id=task.id + "-b", goal=task.goal + " again")
            receipt = sign_handoff(key, delivered, nonce)
        reason = ex.accept(delivered, receipt, case["now"])
    if reason != "OK":
        return "REFUSED", reason
    run = ex.run(delivered, case["plan"])
    if run.outcome == "REFUSED":
        return "REFUSED", run.reason
    trace, final = run.trace, run.final
    if "splice" in case:
        trace, final = apply_splice(trace, final, case["splice"])
    verdict = verify_trace(trace, final, delivered.id)
    return ("COMPLETED", "OK") if verdict == "OK" else ("REFUSED", verdict)


def safe_case(case, key):
    try:
        return run_case(case, key)
    except Exception as e:  # a crash is a mismatch, never a pass
        return "CRASH", type(e).__name__


def load_cases():
    return [json.loads(line) for line in (HERE / "cases.jsonl").read_text().splitlines() if line.strip()]


def main():
    key = load_key(HERE / "fixtures" / "test_key.txt")
    cases = load_cases()
    digest = hashlib.sha256((HERE / "cases.jsonl").read_bytes()).hexdigest()
    stats, lat, bad = {}, [], []
    for c in cases:
        t0 = time.perf_counter()
        got = safe_case(c, key)
        lat.append((time.perf_counter() - t0) * 1000)
        want = (c["expect"]["outcome"], c["expect"]["reason"])
        s = stats.setdefault(c["class"], {"n": 0, "refused": 0, "completed": 0, "match": 0, "want": set()})
        s["n"] += 1
        s["refused"] += got[0] == "REFUSED"
        s["completed"] += got[0] == "COMPLETED"
        s["match"] += got == want
        s["want"].add(want[0])
        if got != want:
            bad.append(f"MISMATCH {c['id']} got={got[0]}/{got[1]} want={want[0]}/{want[1]}")
    print("| class | cases | refused | completed | expected | match |")
    print("|---|---|---|---|---|---|")
    for cls in CLASSES + sorted(set(stats) - set(CLASSES)):
        s = stats.get(cls, {"n": 0, "refused": 0, "completed": 0, "match": 0, "want": set()})
        print(f"| {cls} | {s['n']} | {s['refused']} | {s['completed']} | {'/'.join(sorted(s['want']))} | {s['match']}/{s['n']} |")
        if cls not in CLASSES:
            bad.append(f"UNKNOWN CLASS {cls}")
        elif s["n"] < 3:
            bad.append(f"CLASS {cls} has {s['n']} cases, want at least 3")
    ok = sum(s["match"] for s in stats.values())
    for line in bad:
        print(line)
    print(f"success: {ok}/{len(cases)}")
    print(f"median latency ms: {statistics.median(lat) if lat else 0:.3f}")
    print(f"cases-sha256: {digest}")
    proof = {"cases": len(cases), "matched": ok,
             "refused": sum(s["refused"] for s in stats.values()),
             "completed": sum(s["completed"] for s in stats.values()),
             "cases_sha256": digest, "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (HERE / "PROOF.json").write_text(json.dumps(proof, indent=2) + "\n")
    return 1 if bad or not cases or ok != len(cases) else 0


if __name__ == "__main__":
    sys.exit(main())
