#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-
#
# Unittests for the se-profile script.

import unittest
from se_profile import run_profiler, get_default_options
from se_profile import MemProfiler


class MemProfilerTests(unittest.TestCase):
    def setUp(self):
        self.options = get_default_options()

    def test_with_limit(self):
        """Test the import limit for a script"""
        self.options.peak_limit = 1
        result = run_profiler(self.options, MemProfiler)



def main():
    suite = unittest.TestSuite()
    suite.addTests(unittest.makeSuite(MemProfilerTests, "test"))

if __name__ == "__main__":
    main()
