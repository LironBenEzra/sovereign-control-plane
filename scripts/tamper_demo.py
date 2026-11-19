#!/usr/bin/env python3
"""Show the verifier catching tampering, on a copy of the audit log.

The real log is never touched. A copy is edited in three ways, and each time the
verifier is run against it:

1. change one recorded decision (for example "block" becomes "allow");
2. delete one record from the middle;
3. cut records off the end (the one thing a hash chain alone cannot see, and the
   reason every API response carries a receipt).

    python scripts/tamper_demo.py --data-dir data
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from control_plane.audit.keys import PUBLIC_KEY_FILE, load_public_key
from control_plane.audit.verify import Report, parse_lines, receipt_problem, verify_log


def describe(report: Report) -> str:
    if report.ok:
        return f"OK      {report.records} records verified, {report.replayed} decisions replayed"
    problem = (report.chain_problems or report.replay_problems)[0]
    return f"FAILED  at record {problem.seq}: {problem.reason}"


def write(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))


def main() -> int:
    parser = argparse.ArgumentParser(description="Show the verifier catching tampering.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    data_dir: Path = parser.parse_args().data_dir

    log_path = data_dir / "audit" / "audit.jsonl"
    policy_dir = data_dir / "policies"
    public_key = load_public_key(data_dir / "keys" / PUBLIC_KEY_FILE)
    records, _ = parse_lines(log_path.read_text(encoding="utf-8").splitlines())
    decisions = [r for r in records if r["event"] == "decision"]
    if len(records) < 4 or not decisions:
        print("The audit log is too short. Run `make demo` first.")
        return 1

    print(f"original log            : {describe(verify_log(log_path, public_key, policy_dir))}")

    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "audit.jsonl"

        # 1. Rewrite a decision.
        edited = json.loads(json.dumps(records))
        target = decisions[-1]["seq"]
        old = edited[target]["body"]["decision"]["action"]
        new = "allow" if old != "allow" else "block"
        edited[target]["body"]["decision"]["action"] = new
        write(copy, edited)
        print(f'record {target}: "{old}" -> "{new}"')
        print(f"  edited copy           : {describe(verify_log(copy, public_key, policy_dir))}")

        # 2. Delete a record.
        middle = len(records) // 2
        write(copy, records[:middle] + records[middle + 1 :])
        print(f"record {middle}: deleted")
        print(f"  edited copy           : {describe(verify_log(copy, public_key, policy_dir))}")

        # 3. Truncate the tail.
        kept = records[:-2]
        write(copy, kept)
        last = records[-1]
        print("last 2 records: cut off")
        print(f"  edited copy           : {describe(verify_log(copy, public_key, policy_dir))}")
        problem = receipt_problem(kept, last["seq"], last["hash"])
        print(f"  with a caller's receipt: FAILED  {problem}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
