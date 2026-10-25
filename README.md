# a2a-handoff-gates

Proves: two scripted Python agents hand one task from a planner agent to an executor agent across a gated boundary, and every unsafe handoff in a planted corpus is refused while every clean one completes. Verify in 60s: `python3 evaluate.py`

## The problem

When one agent hands a task to another, the receiving agent usually trusts the message. A task that was edited in transit, sent twice, left sitting past its deadline, or never signed looks the same as a good one. Once the executor starts, nothing checks each tool call against what the task allowed, so a widened tool list or an over budget run is only noticed afterward, if at all.

## Run it (60s)

```
python3 -m pip install pytest
bash run.sh
```

`run.sh` honors `PY`, for example `PY=python3.12 bash run.sh`. It runs `python3 evaluate.py`, then `python3 -m pytest -q`, then `python3 mutants.py`, and exits 0 only if all three pass. The standard library is enough for `evaluate.py` and `mutants.py`. `tests/test_gates.py` also runs as a plain script, `python3 tests/test_gates.py`, if pytest is not installed.

`evaluate.py` printed:

```
| class | cases | refused | completed | expected | match |
|---|---|---|---|---|---|
| CLEAN | 4 | 0 | 4 | COMPLETED | 4/4 |
| UNSIGNED | 3 | 3 | 0 | REFUSED | 3/3 |
| TAMPERED | 5 | 5 | 0 | REFUSED | 5/5 |
| REPLAYED | 3 | 3 | 0 | REFUSED | 3/3 |
| EXPIRED | 3 | 3 | 0 | REFUSED | 3/3 |
| TOOL_NOT_ALLOWED | 3 | 3 | 0 | REFUSED | 3/3 |
| ARG_OUT_OF_SCHEMA | 4 | 4 | 0 | REFUSED | 4/4 |
| BUDGET_EXCEEDED | 3 | 3 | 0 | REFUSED | 3/3 |
| TRACE_SPLICED | 7 | 7 | 0 | REFUSED | 7/7 |
success: 35/35
median latency ms: 0.062
cases-sha256: 7bb11563b8798a0ddce1235895e5e4991d58a5c48904b3120b643f028413f3e3
```

It also writes `PROOF.json` with the counts, the cases hash and a timestamp. Latency varies by machine. The cases hash changes only when `cases.jsonl` changes. `RED-RUN-1.txt` is an earlier run where one case carried a wrong expected value on purpose. It printed `MISMATCH clean-01`, `success: 34/35` and exited 1.

`python3 mutants.py` printed:

```
control: unmodified copy passes evaluate.py
CAUGHT sig-verify: HMAC signature compare
CAUGHT unsigned: missing or empty receipt
CAUGHT freshness: deadline check
CAUGHT nonce-ledger: nonce already seen
CAUGHT tool-allowlist: tool in allowed_tools
CAUGHT arg-schema: argument allowlist
CAUGHT budget: max tool calls
CAUGHT hash-chain: trace hash chain
CAUGHT auth-before-call: authorization record before each call
CAUGHT final-result-hash: final result equals recorded hash
mutants: caught 10/10
```

## How it works

Prior art is the A2A protocol (Google) for agent to agent messaging and AgentDojo for testing agents against attacks. Both are named here and neither is claimed. This repo reuses neither, and it does not implement the A2A wire format.

`planner.py` is the planner agent. It builds a `Task` (id, goal, allowed tools, a budget of maximum tool calls, a deadline) and signs a `HandoffReceipt` with HMAC-SHA256 over the canonical JSON of the task plus a nonce. The key is read from `fixtures/test_key.txt` by the caller and is never written into product code. The same file holds the three small helpers every gate shares: `canon` (sorted keys, no spaces), `sha`, and `link`, which extends the hash chain.

`executor.py` is the executor agent. `accept` takes a handoff only if the receipt is present, the HMAC verifies, the deadline has not passed, and the nonce has not been seen. A refused handoff does not use up its nonce. `run` then walks a scripted plan. Before every tool call `authorize` checks that the tool is in `allowed_tools`, that the arguments match the plain allowlist for that tool, and that the call count is under the budget. Each step appends an authorization record and, if allowed, a call record. Every record carries `prev_hash` and `hash`, so the trace is a hash chain. A denial is recorded and the run stops.

`tools.py` holds three sandboxed fake tools, `lookup_record`, `compute_total` and `write_result`, over in-memory dicts, and the argument allowlist for each. They touch no file, network or process.

`verify_trace.py` takes a finished trace and re-derives the chain from the first record. It then checks that every call record has an earlier allow record for the same step, tool and argument hash, and that the final result equals the hash recorded by the last `write_result` call. It returns `OK` or one reason code.

`cases.jsonl` holds the planted corpus, one JSON object per line, each with a labeled outcome and reason code. `evaluate.py` runs every case through the whole path, builds the splice attacks for the `TRACE_SPLICED` class, prints the table, and exits 1 on any mismatch or any class with fewer than 3 cases. A crash counts as a mismatch. `mutants.py` copies the repo to a temp directory, disables one check per copy, and requires `evaluate.py` to fail on each. `tests/test_gates.py` has one test per failure class plus one clean test, each with its own inline case, and one test that replays the whole corpus.

## What each planted case proves

| Class | Cases | Reason code | What it proves |
|---|---|---|---|
| CLEAN | 4 | OK | A signed, fresh, in schema, in budget handoff completes. Includes a run at exactly the deadline second and a run that uses the whole budget. |
| UNSIGNED | 3 | UNSIGNED | No receipt, or a receipt with an empty signature, is refused before anything runs. |
| TAMPERED | 5 | BAD_SIGNATURE | A goal, tool list, budget or deadline changed after signing is refused. The deadline case also shows the signature is checked before freshness. |
| REPLAYED | 3 | REPLAYED_NONCE | The same handoff delivered twice runs once. A second task signed under a reused nonce is also refused. |
| EXPIRED | 3 | EXPIRED | A handoff delivered after its deadline is refused. |
| TOOL_NOT_ALLOWED | 3 | TOOL_NOT_ALLOWED | A call to a tool outside `allowed_tools`, including an empty list and a tool that does not exist, is refused before it runs. |
| ARG_OUT_OF_SCHEMA | 4 | ARG_OUT_OF_SCHEMA | An unknown record id, an extra argument, a wrong type, and a disallowed result key are each refused. |
| BUDGET_EXCEEDED | 3 | BUDGET_EXCEEDED | The call after the last permitted one is refused, including a budget of zero. |
| TRACE_SPLICED | 7 | TRACE_CHAIN_BROKEN, TRACE_UNAUTHORIZED_CALL, TRACE_RESULT_MISMATCH | A finished trace with a record swapped, inserted or dropped fails. Edits that leave the chain intact (an attacker who rewrites every hash) are caught by the authorization and result checks. A changed final result fails. |

## Mutants

Each mutant disables one check in a temp copy. `evaluate.py` must then exit nonzero. A control copy with no change must pass first, and each mutant must still be valid Python.

| Mutant | Check disabled | Caught |
|---|---|---|
| sig-verify | HMAC signature compare | yes |
| unsigned | missing or empty receipt | yes |
| freshness | deadline check | yes |
| nonce-ledger | nonce already seen | yes |
| tool-allowlist | tool in allowed_tools | yes |
| arg-schema | argument allowlist | yes |
| budget | max tool calls | yes |
| hash-chain | trace hash chain | yes |
| auth-before-call | authorization record before each call | yes |
| final-result-hash | final result equals recorded hash | yes |

## Honesty

Both agents are scripted Python functions. No language model is in the loop. The tasks and tools are synthetic and written for this repo. The key is a test fixture and is not a secret. Everything runs in one process with an in-memory nonce ledger and a clock passed in as an integer. There is no real A2A protocol wire format, no network, and no transport between the agents. This proves the gate design on a planted corpus. It is not an integration with any agent framework.

## Limitations

- One shared key means anyone who can verify a handoff can also sign one. Real use wants a key per agent or an asymmetric signature.
- A planner that holds the key can sign a harmful task that is still inside the schema. The gates check that the executor stays within what was signed, not whether the signed task is a good idea.
- The hash chain proves the records agree with each other. An attacker who can rewrite the whole trace and also the final result can produce a consistent forgery. Records dropped from the end of a trace that does not include the last `write_result` are not detected. A head hash stored somewhere the executor cannot write would close this, and it is not built.
- The nonce ledger lives in one process and is lost on restart.
- The argument allowlist is a fixed table for three tools. It is not a schema language.
- Freshness uses the executor's clock value as given. It does not defend against a wrong clock.

## Hostile review

Questions a sceptical senior engineer would ask.

1. Did you write the cases and the code, so of course they agree? Yes. The cases show that each check fires on the input it was written for. The mutants show that removing any one check changes the result, so no check is decoration. Neither shows the corpus is complete.
2. Why is a refusal in the middle of a run still counted as refused? The executor stops at the first denied call, but earlier calls in that run already ran against the fake tools. For real tools with side effects you would need the budget and schema checks before the first call, or a way to undo. This repo only claims the denied call never runs.
3. What stops a malicious planner? Nothing here. A planner with the key can sign any task. The gate holds the executor to the signed limits and nothing more.
4. Does a valid chain mean the trace is true? No. It means the records are consistent with each other and with the final result. A process that writes the trace and the result together can lie, and a trace cut short at the end can still verify. See Limitations.
5. Does this work with real A2A traffic? Not shown. There is no wire format, transport, authentication of the sender beyond the shared key, or concurrency here. The checks would have to be rebuilt around a real message format.

## CI

The workflow in `.github/workflows/ci.yml` runs `python evaluate.py`, `python -m pytest -q` and `python mutants.py` on push and pull request.

## License

MIT, see LICENSE.

Agent verification contract: [AGENTS.md](AGENTS.md)
