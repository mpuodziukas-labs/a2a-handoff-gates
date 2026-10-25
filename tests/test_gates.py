"""One test per failure class plus one clean run. Each builds its case inline, so none of them
depends on cases.jsonl. The last test replays the whole corpus. Runs under pytest, or as a plain
script: python3 tests/test_gates.py"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import evaluate  # noqa: E402
from planner import load_key  # noqa: E402

KEY = load_key(ROOT / "fixtures" / "test_key.txt")
ALL = ["lookup_record", "compute_total", "write_result"]
PLAN = [
    {"tool": "lookup_record", "args": {"record_id": "r1"}},
    {"tool": "write_result", "args": {"key": "total", "value": 15}},
]


def run(task=None, **over):
    t = {"id": "t-x", "goal": "g", "allowed_tools": ALL, "max_calls": 2, "deadline": 100}
    t.update(task or {})
    case = {"id": "x", "class": "X", "task": t, "plan": PLAN, "now": 100}
    case.update(over)
    return evaluate.run_case(case, KEY)


def test_clean():
    assert run() == ("COMPLETED", "OK")


def test_unsigned():
    assert run(sign="none") == ("REFUSED", "UNSIGNED")
    assert run(sign="empty") == ("REFUSED", "UNSIGNED")


def test_tampered():
    assert run(tamper={"goal": "other"}) == ("REFUSED", "BAD_SIGNATURE")
    assert run(tamper={"max_calls": 9}) == ("REFUSED", "BAD_SIGNATURE")


def test_replayed():
    assert run(replay="same") == ("REFUSED", "REPLAYED_NONCE")
    assert run(replay="reuse_nonce") == ("REFUSED", "REPLAYED_NONCE")


def test_expired():
    assert run(now=101) == ("REFUSED", "EXPIRED")


def test_tool_not_allowed():
    assert run(task={"allowed_tools": ["lookup_record"]}) == ("REFUSED", "TOOL_NOT_ALLOWED")


def test_arg_out_of_schema():
    bad = [{"tool": "lookup_record", "args": {"record_id": "r9"}}] + PLAN[1:]
    assert run(plan=bad) == ("REFUSED", "ARG_OUT_OF_SCHEMA")


def test_budget_exceeded():
    assert run(task={"max_calls": 1}) == ("REFUSED", "BUDGET_EXCEEDED")


def test_trace_spliced():
    swap = {"kind": "swap", "index": 1, "field": "result_sha", "value": "0" * 64}
    assert run(splice=swap) == ("REFUSED", "TRACE_CHAIN_BROKEN")
    drop = {"kind": "drop", "index": 2, "rechain": True}
    assert run(splice=drop) == ("REFUSED", "TRACE_UNAUTHORIZED_CALL")
    assert run(splice={"kind": "final", "value": 1}) == ("REFUSED", "TRACE_RESULT_MISMATCH")


def test_corpus_matches():
    cases = evaluate.load_cases()
    assert len(cases) >= 24
    for c in cases:
        want = (c["expect"]["outcome"], c["expect"]["reason"])
        assert evaluate.safe_case(c, KEY) == want, c["id"]


if __name__ == "__main__":
    failed = 0
    names = sorted(n for n in dir() if n.startswith("test_"))
    for n in names:
        try:
            globals()[n]()
            print("PASS", n)
        except AssertionError as e:
            failed += 1
            print("FAIL", n, e)
    print(f"{len(names) - failed}/{len(names)} tests passed")
    sys.exit(1 if failed else 0)
