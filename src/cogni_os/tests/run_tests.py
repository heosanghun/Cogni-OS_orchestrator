#!/usr/bin/env python3
import sys
import os
import unittest
import io

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover("src/cogni_os/tests")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0)
    result = runner.run(suite)
    if result.wasSuccessful():
        sys.stdout.write("PASSED_ALL_TESTS\n")
        sys.exit(0)
    else:
        sys.stdout.write("FAILED_SOME_TESTS\n")
        sys.exit(1)
