#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Offline verification tool for MCP governance receipt chains.

Verifies Ed25519 signatures, RFC 8785 JCS canonical payloads, and
hash-chain contiguity from a JSON export file.  No network access
or running AGT infrastructure is required.

Usage:
    python scripts/verify_receipts.py receipts.json
"""

import argparse
import json
import sys
from typing import Any, Dict, List

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    verify_receipt,
)


def _reconstruct(data: Dict[str, Any]) -> GovernanceReceipt:
    """Build a GovernanceReceipt from an exported dict."""
    return GovernanceReceipt(
        receipt_id=data.get("receipt_id", ""),
        tool_name=data.get("tool_name", ""),
        agent_did=data.get("agent_did", ""),
        cedar_policy_id=data.get("cedar_policy_id", ""),
        cedar_decision=data.get("cedar_decision", "deny"),
        args_hash=data.get("args_hash", ""),
        timestamp=data.get("timestamp", 0.0),
        session_id=data.get("session_id"),
        parent_receipt_hash=data.get("parent_receipt_hash"),
        signature=data.get("signature"),
        signer_public_key=data.get("signer_public_key"),
        error=data.get("error"),
    )


_EXIT_OK = 0
_EXIT_CHAIN_ERROR = 1
_EXIT_LOAD_ERROR = 2


def verify_chain(
    receipts_data: List[Dict[str, Any]],
) -> tuple[int, List[Dict[str, Any]]]:
    """Verify a chain of exported receipts.

    Returns:
        Tuple of (exit_code, per_receipt_results).
        exit_code is 0 for a fully valid chain, 1 for integrity errors.
        per_receipt_results contains per-receipt check details for JSON output.
    """
    if not receipts_data:
        print("  (empty chain — nothing to verify)")
        return _EXIT_OK, []

    total_errors = 0
    expected_parent_hash = None
    results: List[Dict[str, Any]] = []

    for i, data in enumerate(receipts_data):
        receipt = _reconstruct(data)
        rid_short = (
            receipt.receipt_id[:12] + "…" if len(receipt.receipt_id) > 12 else receipt.receipt_id
        )
        print(f"  [{i}] Receipt {rid_short}  (tool: {receipt.tool_name})")

        receipt_errors: List[str] = []

        # 1. Hash chain contiguity
        if receipt.parent_receipt_hash != expected_parent_hash:
            exp = (expected_parent_hash or "None")[:16]
            got = (receipt.parent_receipt_hash or "None")[:16]
            msg = f"Hash chain broken — expected {exp}…, got {got}…"
            print(f"      ❌  {msg}")
            receipt_errors.append(msg)
        else:
            print("      ✅  Hash chain contiguous")

        # 2. Canonical payload hash (round-trip check)
        stored_hash = data.get("payload_hash")
        if stored_hash and receipt.payload_hash() != stored_hash:
            msg = "Payload hash mismatch (canonical re-generation differs)"
            print(f"      ❌  {msg}")
            receipt_errors.append(msg)
        else:
            print("      ✅  Payload hash verified")

        # 3. Ed25519 signature
        if receipt.signature:
            if verify_receipt(receipt):
                print("      ✅  Ed25519 signature valid")
            else:
                msg = "Ed25519 signature verification failed"
                print(f"      ❌  {msg}")
                receipt_errors.append(msg)
        else:
            print("      ⚠️   Unsigned receipt (no signature)")

        total_errors += len(receipt_errors)
        expected_parent_hash = receipt.payload_hash()
        results.append(
            {
                "index": i,
                "receipt_id": receipt.receipt_id,
                "tool_name": receipt.tool_name,
                "passed": len(receipt_errors) == 0,
                "errors": receipt_errors,
            }
        )
        print()

    exit_code = _EXIT_OK if total_errors == 0 else _EXIT_CHAIN_ERROR
    return exit_code, results


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Verify MCP governance receipt chains offline.",
    )
    parser.add_argument(
        "receipts_file",
        help="Path to JSON file containing exported receipts (from ReceiptStore.export())",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON for CI/CD integration (includes per-receipt detail)",
    )
    args = parser.parse_args()

    if not args.json_output:
        print()
        print("╔══════════════════════════════════════════════════════╗")
        print("║  MCP Receipt Chain — Offline Verification           ║")
        print("╚══════════════════════════════════════════════════════╝")
        print()

    try:
        with open(args.receipts_file) as f:
            receipts_data = json.load(f)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc), "exit_code": _EXIT_LOAD_ERROR}, indent=2))
        else:
            print(f"  Error loading {args.receipts_file}: {exc}")
        return _EXIT_LOAD_ERROR

    if not args.json_output:
        print(f"  Loaded {len(receipts_data)} receipt(s) from {args.receipts_file}")
        print()

    exit_code, per_receipt = verify_chain(receipts_data)

    if args.json_output:
        output = {
            "file": args.receipts_file,
            "total_receipts": len(receipts_data),
            "passed": exit_code == _EXIT_OK,
            "exit_code": exit_code,
            "receipts": per_receipt,
        }
        print(json.dumps(output, indent=2))
    elif exit_code == _EXIT_OK:
        print("  🎉 Verification passed — chain is contiguous and signatures are valid.")
    else:
        print("  🚨 Verification failed — the receipt chain has integrity issues.")

    if not args.json_output:
        print()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
