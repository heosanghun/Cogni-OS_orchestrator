#!/usr/bin/env python3
import sys
import os
import unittest

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover("src/cogni_os/tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
