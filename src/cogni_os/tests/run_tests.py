#!/usr/bin/env python3
import sys
import pathlib

# Ensure src directory is on python path for trusted verification
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

import unittest

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover("src/cogni_os/tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
