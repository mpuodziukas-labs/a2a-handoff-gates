"""Planner agent: builds a Task and signs the handoff receipt.
Also holds the canonical forms (canon, sha, link) that the executor and the trace verifier share."""
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

GENESIS = "0" * 64


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(o):
    return hashlib.sha256(canon(o).encode()).hexdigest()


def link(prev, body):
    """Hash chain link: sha256 of the previous hash followed by the canonical record body."""
    return hashlib.sha256((prev + canon(body)).encode()).hexdigest()


@dataclass
class Task:
    id: str
    goal: str
    allowed_tools: list
    max_calls: int
    deadline: int


@dataclass
class HandoffReceipt:
    nonce: str
    sig: str


def mac(key, task, nonce):
    msg = canon({"task": asdict(task), "nonce": nonce})
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def build_task(task_id, goal, allowed_tools, max_calls, deadline):
    return Task(task_id, goal, list(allowed_tools), max_calls, deadline)


def sign_handoff(key, task, nonce):
    return HandoffReceipt(nonce, mac(key, task, nonce))


def load_key(path):
    with open(path, "rb") as f:
        return f.read().strip()
