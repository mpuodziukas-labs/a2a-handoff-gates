"""Three sandboxed fake tools over in-memory dicts. No file, network or process access."""
RECORDS = {"r1": {"qty": 3, "price": 5}, "r2": {"qty": 2, "price": 7}, "r3": {"qty": 10, "price": 1}}
IDS = list(RECORDS)

# Plain allowlist per tool: argument name -> (type, allowed values or None for any value of that type).
SCHEMA = {
    "lookup_record": {"record_id": (str, IDS)},
    "compute_total": {"record_ids": (list, IDS)},
    "write_result": {"key": (str, ["total"]), "value": (int, None)},
}


def lookup_record(args, store):
    return dict(RECORDS.get(args.get("record_id"), {}))


def compute_total(args, store):
    rows = [RECORDS.get(i, {"qty": 0, "price": 0}) for i in args.get("record_ids", [])]
    return {"total": sum(r["qty"] * r["price"] for r in rows)}


def write_result(args, store):
    store[args.get("key")] = args.get("value")
    return {"key": args.get("key"), "value": args.get("value")}


TOOLS = {"lookup_record": lookup_record, "compute_total": compute_total, "write_result": write_result}
