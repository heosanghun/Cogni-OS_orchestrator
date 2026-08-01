{
  "schema_version": 1,
  "artifacts": [
    {
      "path": "P11-RELEASE.verifier-report.md",
      "sha256": "6a9364a886c6a6ba52c78a632874d44a8bf733dbfb3e12d0c46dd5f167c75dab"
    }
  ],
  "validations": [
    {
      "command": "C:\\Project\\Deep Equilibrium8\\python_dist\\python.exe src/cogni_os/tests/run_tests.py",
      "command_argv": ["C:\\Project\\Deep Equilibrium8\\python_dist\\python.exe", "src/cogni_os/tests/run_tests.py"],
      "exit_code": 0,
      "passed": 58,
      "failed": 0,
      "skipped": 0,
      "skip_reasons": [],
      "raw_output_path": "P11-RELEASE_raw_output.txt",
      "raw_output_sha256": "380cc5688343ca1fab822e9cfe344e1e31577c42f583297abf8f2429f1bab0c7"
    }
  ],
  "known_answer_checks": [
    {
      "name": "P11_Verifier_Known_Answer",
      "expected": "pass",
      "observed": "pass",
      "passed": true
    }
  ],
  "claims": [
    {
      "name": "verifier_check",
      "kind": "functional",
      "measured": true,
      "value": "pass",
      "evidence": ["P11-RELEASE.verifier-report.md"]
    }
  ]
}
