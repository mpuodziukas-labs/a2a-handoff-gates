"""Trace verifier: re-derives the hash chain, checks every call had an earlier allow record for the
same step, tool and arguments, and checks the final result against what write_result recorded."""
from planner import GENESIS, link, sha


def verify_trace(trace, final, task_id):
    """Returns "OK" or a reason code."""
    prev = GENESIS
    for rec in trace:
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("task") != task_id or rec.get("prev_hash") != prev or rec.get("hash") != link(prev, body):
            return "TRACE_CHAIN_BROKEN"
        prev = rec["hash"]
    allowed, last_write = set(), None
    for rec in trace:
        key = (rec.get("step"), rec.get("tool"), rec.get("args_sha"))
        if rec.get("kind") == "auth" and rec.get("decision") == "allow":
            allowed.add(key)
        elif rec.get("kind") == "call":
            if key not in allowed:
                return "TRACE_UNAUTHORIZED_CALL"
            if rec.get("tool") == "write_result":
                last_write = rec
    if final is None or last_write is None or sha(final) != last_write.get("result_sha"):
        return "TRACE_RESULT_MISMATCH"
    return "OK"
