#!/usr/bin/env python3
import sys
import os

# Absolute path resolution for trusted sandbox verification
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import unittest

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(current_dir)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
