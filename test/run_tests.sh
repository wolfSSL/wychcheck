#!/bin/sh
# Meta-tests: verify that wychcheck correctly reports pass/fail.
# Requires wychcheck to be built already (./build/wychcheck).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WYCHCHECK="$PROJECT_DIR/build/wychcheck"

if [ ! -x "$WYCHCHECK" ]; then
    echo "FAIL: $WYCHCHECK not found or not executable" >&2
    echo "Build the project first: cmake -B build && cmake --build build" >&2
    exit 2
fi

pass=0
fail=0

run_test() {
    name="$1"
    vectors_dir="$2"
    expect_exit="$3"    # 0 = expect all pass, 1 = expect failures
    expect_grep="$4"    # optional: grep pattern that must appear in output

    # wychcheck looks for testvectors_v1/ under WYCHEPROOF_DIR, so wrap
    # our fixture dir behind that expected path via a symlink
    tmpdir=$(mktemp -d)
    ln -s "$vectors_dir" "$tmpdir/testvectors_v1"
    output=$(WYCHEPROOF_DIR="$tmpdir" "$WYCHCHECK" 2>&1) && actual_exit=0 || actual_exit=$?
    rm -rf "$tmpdir"

    if [ "$actual_exit" -ne "$expect_exit" ]; then
        echo "FAIL  $name: expected exit $expect_exit, got $actual_exit"
        echo "      output: $output"
        fail=$((fail + 1))
        return
    fi

    if [ -n "$expect_grep" ]; then
        if ! echo "$output" | grep -q "$expect_grep"; then
            echo "FAIL  $name: expected output to contain '$expect_grep'"
            echo "      output: $output"
            fail=$((fail + 1))
            return
        fi
    fi

    echo "PASS  $name"
    pass=$((pass + 1))
}

# Test 1: all-pass vectors should produce exit 0
run_test "all vectors pass" \
    "$SCRIPT_DIR/vectors_pass" \
    0 \
    "0 failed"

# Test 2: rigged-to-fail vectors should produce exit 1
run_test "detects valid-with-wrong-ct failure" \
    "$SCRIPT_DIR/vectors_fail" \
    1 \
    "FAIL"

# Test 3: verify specific tcId appears in failure output
run_test "failure output includes tcId=1" \
    "$SCRIPT_DIR/vectors_fail" \
    1 \
    "tcId=1"

# Test 4: verify specific tcId=2 (invalid-but-valid) appears in failure output
run_test "failure output includes tcId=2" \
    "$SCRIPT_DIR/vectors_fail" \
    1 \
    "tcId=2"

echo ""
echo "--- meta-test summary ---"
echo "$pass passed, $fail failed"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
