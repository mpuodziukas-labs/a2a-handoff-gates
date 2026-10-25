"""Executor agent: accepts a handoff only if it is signed, authentic, fresh and unseen, then runs a
scripted plan. A pre-action authorizer gates every tool call, and every step is appended to a hash chain."""
import hmac
from dataclasses import dataclass

import tools
from planner import GENESIS, link, mac, sha


@dataclass
class Run:
    outcome: str
    reason: str
    trace: list
    final: object


def args_ok(tool, args):
    spec = tools.SCHEMA.get(tool)
    if spec is None or not isinstance(args, dict) or set(args) != set(spec):
        return False
    for name, (typ, allowed) in spec.items():
        v = args[name]
        if type(v) is not typ:
            return False
        if allowed is not None and not all(i in allowed for i in (v if typ is list else [v])):
            return False
    return True


def authorize(task, tool, args, calls):
    """Returns None to allow, or a reason code to refuse."""
    if tool not in task.allowed_tools or tool not in tools.TOOLS:
        return "TOOL_NOT_ALLOWED"
    if not args_ok(tool, args):
        return "ARG_OUT_OF_SCHEMA"
    if calls >= task.max_calls:
        return "BUDGET_EXCEEDED"
    return None


class Executor:
    def __init__(self, key):
        self.key = key
        self.seen = set()  # nonce ledger

    def accept(self, task, receipt, now):
        """Returns "OK" or a reason code. A refused handoff does not use up its nonce."""
        if receipt is None or not receipt.sig:
            return "UNSIGNED"
        want = mac(self.key, task, receipt.nonce)
        if not hmac.compare_digest(want, receipt.sig):
            return "BAD_SIGNATURE"
        if now > task.deadline:
            return "EXPIRED"
        if receipt.nonce in self.seen:
            return "REPLAYED_NONCE"
        self.seen.add(receipt.nonce)
        return "OK"

    def run(self, task, plan):
        trace, store, calls, final = [], {}, 0, None

        def add(rec):
            rec["task"] = task.id
            rec["prev_hash"] = trace[-1]["hash"] if trace else GENESIS
            rec["hash"] = link(rec["prev_hash"], rec)
            trace.append(rec)

        for i, step in enumerate(plan):
            tool, args = step["tool"], step["args"]
            why = authorize(task, tool, args, calls)
            add({"kind": "auth", "step": i, "tool": tool, "args_sha": sha(args),
                 "decision": "deny" if why else "allow", "reason": why or "OK"})
            if why:
                return Run("REFUSED", why, trace, None)
            out = tools.TOOLS[tool](args, store)
            calls += 1
            add({"kind": "call", "step": i, "tool": tool, "args_sha": sha(args), "result_sha": sha(out)})
            if tool == "write_result":
                final = out
        return Run("COMPLETED", "OK", trace, final)
