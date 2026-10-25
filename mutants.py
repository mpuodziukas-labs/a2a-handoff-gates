"""Mutation check: disable one gate at a time in a temp copy, then evaluate.py must exit nonzero.
An unmodified control copy must pass first. A mutant that hangs past 30 s counts as caught.
Set MUTANT_TMP to choose where the temp copies go."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).parent
# (name, check disabled, file, text to take out, text to put in)
MUTANTS = [
    ("sig-verify", "HMAC signature compare", "executor.py",
     "if not hmac.compare_digest(want, receipt.sig):", "if False:"),
    ("unsigned", "missing or empty receipt", "executor.py",
     "if receipt is None or not receipt.sig:", "if False:"),
    ("freshness", "deadline check", "executor.py",
     "if now > task.deadline:", "if False:"),
    ("nonce-ledger", "nonce already seen", "executor.py",
     "if receipt.nonce in self.seen:", "if False:"),
    ("tool-allowlist", "tool in allowed_tools", "executor.py",
     "if tool not in task.allowed_tools or tool not in tools.TOOLS:", "if tool not in tools.TOOLS:"),
    ("arg-schema", "argument allowlist", "executor.py",
     "if not args_ok(tool, args):", "if False:"),
    ("budget", "max tool calls", "executor.py",
     "if calls >= task.max_calls:", "if False:"),
    ("hash-chain", "trace hash chain", "verify_trace.py",
     'if rec.get("task") != task_id or rec.get("prev_hash") != prev or rec.get("hash") != link(prev, body):',
     "if False:"),
    ("auth-before-call", "authorization record before each call", "verify_trace.py",
     "if key not in allowed:", "if False:"),
    ("final-result-hash", "final result equals recorded hash", "verify_trace.py",
     'if final is None or last_write is None or sha(final) != last_write.get("result_sha"):',
     "if final is None or last_write is None:"),
]


def fresh(base, name):
    dst = pathlib.Path(base) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "PROOF.json"))
    return dst


def evaluate_rc(tree):
    try:
        r = subprocess.run([sys.executable, "evaluate.py"], cwd=tree, capture_output=True, timeout=30,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124
    return r.returncode


def main():
    caught = 0
    with tempfile.TemporaryDirectory(dir=os.environ.get("MUTANT_TMP") or None) as tmp:
        if evaluate_rc(fresh(tmp, "control")) != 0:
            print("control FAIL: unmodified copy does not pass evaluate.py")
            return 1
        print("control: unmodified copy passes evaluate.py")
        for i, (name, check, f, old, new) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1")
                return 1
            mutated = src.replace(old, new)
            compile(mutated, f, "exec")  # a mutant that is a syntax error proves nothing
            (tree / f).write_text(mutated)
            red = evaluate_rc(tree) != 0
            caught += red
            print(f"{'CAUGHT' if red else 'LIVE  '} {name}: {check}")
    print(f"mutants: caught {caught}/{len(MUTANTS)}")
    return 0 if caught == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
