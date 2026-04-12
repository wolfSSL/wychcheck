#!/usr/bin/env python3
"""Merge NIST ACVP prompt.json + expectedResults.json into a single
self-contained JSON file that the wolfcrypt-check mldsa_acvp runner can read.

Usage:
    python3 tools/merge_acvp.py

Reads from  testvectors_acvp/<Op>/<Op>/prompt.json + expectedResults.json
Writes to   testvectors_acvp/<Op>.json
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
ACVP_DIR = os.path.join(PROJECT_DIR, "testvectors_acvp")

OPERATIONS = [
    ("ML-DSA-keyGen-FIPS204", "mldsa_acvp_keygen.json"),
    ("ML-DSA-sigVer-FIPS204", "mldsa_acvp_sigver.json"),
    ("ML-DSA-sigGen-FIPS204", "mldsa_acvp_siggen.json"),
]


def merge(op_dir, schema_name, out_path):
    prompt_path = os.path.join(ACVP_DIR, op_dir, "prompt.json")
    expected_path = os.path.join(ACVP_DIR, op_dir, "expectedResults.json")

    with open(prompt_path) as f:
        prompt = json.load(f)
    with open(expected_path) as f:
        expected = json.load(f)

    # Build lookup: tgId -> tcId -> {expected fields (minus tcId)}
    exp_by_tg = {}
    for g in expected["testGroups"]:
        tg_id = g["tgId"]
        exp_by_tg[tg_id] = {}
        for tc in g["tests"]:
            tc_id = tc["tcId"]
            extra = {k: v for k, v in tc.items() if k != "tcId"}
            exp_by_tg[tg_id][tc_id] = extra

    # Inject expected fields into each prompt test case
    for g in prompt["testGroups"]:
        tg_id = g["tgId"]
        for tc in g["tests"]:
            tc_id = tc["tcId"]
            if tg_id in exp_by_tg and tc_id in exp_by_tg[tg_id]:
                tc.update(exp_by_tg[tg_id][tc_id])

    prompt["schema"] = schema_name

    with open(out_path, "w") as f:
        json.dump(prompt, f, separators=(",", ":"))

    n_groups = len(prompt["testGroups"])
    n_tests = sum(len(g["tests"]) for g in prompt["testGroups"])
    print(f"  {os.path.basename(out_path)}: {n_groups} groups, {n_tests} tests")


def main():
    print("Merging ACVP prompt + expectedResults...")
    for op_dir, schema_name in OPERATIONS:
        out_path = os.path.join(ACVP_DIR, schema_name.replace(".json", "_test.json"))
        merge(op_dir, schema_name, out_path)
    print("Done.")


if __name__ == "__main__":
    main()
