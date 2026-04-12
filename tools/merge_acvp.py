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
    # Each entry: (acvp_op_dir, schema_name)
    # schema_name serves two roles:
    #   1. Injected as prompt["schema"] into the merged JSON — must exactly
    #      match a key in main.c's runners[] dispatch table.
    #   2. Determines the output filename: schema_name[:-5] + "_test.json"
    #      (e.g. "mldsa_acvp_keygen.json" -> "mldsa_acvp_keygen_test.json").
    # These two uses are coupled: using the _test.json filename as schema_name
    # would produce JSON the runner silently skips at runtime.
    ("ML-DSA-keyGen-FIPS204", "mldsa_acvp_keygen.json"),
    ("ML-DSA-sigVer-FIPS204", "mldsa_acvp_sigver.json"),
    ("ML-DSA-sigGen-FIPS204", "mldsa_acvp_siggen.json"),
    # ML-KEM (FIPS 203) — vectors must be downloaded to testvectors_acvp/
    ("ML-KEM-keyGen-FIPS203",     "mlkem_acvp_keygen.json"),
    ("ML-KEM-encapDecap-FIPS203", "mlkem_acvp_encapdecap.json"),
    # SLH-DSA (FIPS 205) — vendored from BoringSSL's bundled NIST ACVP vectors
    ("SLH-DSA-keyGen-FIPS205", "slhdsa_acvp_keygen.json"),
    ("SLH-DSA-sigVer-FIPS205", "slhdsa_acvp_sigver.json"),
    ("SLH-DSA-sigGen-FIPS205", "slhdsa_acvp_siggen.json"),
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
            else:
                print(f"  WARNING: no expectedResults entry for tgId={tg_id} tcId={tc_id}",
                      file=sys.stderr)

    prompt["schema"] = schema_name

    with open(out_path, "w") as f:
        json.dump(prompt, f, separators=(",", ":"))

    n_groups = len(prompt["testGroups"])
    n_tests = sum(len(g["tests"]) for g in prompt["testGroups"])
    print(f"  {os.path.basename(out_path)}: {n_groups} groups, {n_tests} tests")


def main():
    print("Merging ACVP prompt + expectedResults...")
    for op_dir, schema_name in OPERATIONS:
        prompt_path = os.path.join(ACVP_DIR, op_dir, "prompt.json")
        if not os.path.exists(prompt_path):
            print(f"  SKIP {op_dir}: vectors not found (download to testvectors_acvp/{op_dir}/)")
            continue
        out_path = os.path.join(ACVP_DIR, schema_name.replace(".json", "_test.json"))
        merge(op_dir, schema_name, out_path)
    print("Done.")


if __name__ == "__main__":
    main()
