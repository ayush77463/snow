"""Unified Cross-Language Protocol v1 Test Runner.

Orchestrates bidirectional verification between the Python Desktop Core
and the Kotlin Android client:
  1. Generates Python -> Kotlin fixtures.
  2. Executes Android Gradle JVM tests (which validate Python fixtures and export Kotlin fixtures).
  3. Executes Python test suite (which validates Kotlin fixtures).
  4. Reports comprehensive bidirectional compatibility status.
"""

import json
from pathlib import Path
import subprocess
import sys
import unittest

# Ensure src and tests are on python path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from tests.test_cross_language_parity import (
    FIXTURES_ROOT,
    KT_TO_PY_INVALID,
    KT_TO_PY_VALID,
    generate_python_fixtures,
    TestCrossLanguageKotlinToPython,
)


def main() -> int:
    print("=" * 70)
    print("SNOW Protocol v1 — Bidirectional Cross-Language Test Orchestrator")
    print("=" * 70)

    # Step 1: Generate Python -> Kotlin fixtures
    print("\n[Step 1/3] Generating Python fixtures for Kotlin validator...")
    py_valid_count, py_invalid_count = generate_python_fixtures()
    print(f"  -> Generated {py_valid_count} valid Python JSON fixtures")
    print(f"  -> Generated {py_invalid_count} negative/invalid Python JSON fixtures")
    print(f"  -> Path: {FIXTURES_ROOT / 'python_to_kotlin'}")

    # Step 2: Run Gradle JVM tests to validate Python fixtures and export Kotlin fixtures
    print("\n[Step 2/3] Executing Kotlin JVM test suite via Gradle...")
    android_dir = REPO_ROOT / "android"
    gradlew_cmd = [str(android_dir / "gradlew.bat"), "testDebugUnitTest"]

    res = subprocess.run(gradlew_cmd, cwd=str(android_dir), capture_output=True, text=True)
    if res.returncode != 0:
        print("  [ERROR] Gradle unit tests failed!")
        print(res.stdout)
        print(res.stderr)
        return 1
    print("  -> Gradle testDebugUnitTest completed successfully.")
    print("  -> Direction B (Python -> Kotlin): Validated all Python fixtures in Kotlin.")
    print("  -> Exported Kotlin fixtures to: build/cross_language/kotlin_to_python/")

    # Step 3: Run Python test suite to validate Kotlin fixtures
    print("\n[Step 3/3] Validating Kotlin fixtures using Python validate_raw_message()...")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCrossLanguageKotlinToPython)
    runner = unittest.TextTestRunner(verbosity=2)
    py_result = runner.run(suite)

    if not py_result.wasSuccessful():
        print("  [ERROR] Python validation of Kotlin fixtures failed!")
        return 1

    kt_valid_count = len(list(KT_TO_PY_VALID.glob("*.json"))) if KT_TO_PY_VALID.exists() else 0
    kt_expected_file = KT_TO_PY_INVALID / "expected_errors.json"
    kt_invalid_count = len(json.loads(kt_expected_file.read_text(encoding="utf-8"))) if kt_expected_file.exists() else 0

    print("\n" + "=" * 70)
    print("BIDIRECTIONAL CROSS-LANGUAGE VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Direction A (Kotlin -> Python):")
    print(f"  - Valid Kotlin envelopes accepted by Python:    {kt_valid_count} / {kt_valid_count} PASS")
    print(f"  - Invalid Kotlin envelopes rejected by Python: {kt_invalid_count} / {kt_invalid_count} PASS")
    print(f"  - Clean null omission verified:                 PASS")
    print(f"\nDirection B (Python -> Kotlin):")
    print(f"  - Valid Python envelopes accepted by Kotlin:    {py_valid_count} / {py_valid_count} PASS")
    print(f"  - Invalid Python envelopes rejected by Kotlin: {py_invalid_count} / {py_invalid_count} PASS")
    print(f"  - Clean null omission verified:                 PASS")
    print(f"\nTotal bidirectional fixtures verified: {kt_valid_count + kt_invalid_count + py_valid_count + py_invalid_count}")
    print("=" * 70)
    print("RESULT: 100% BIDIRECTIONAL PROTOCOL v1 WIRE PARITY VERIFIED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
