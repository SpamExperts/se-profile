#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-
#
# Unittests for the se-profile script.
import unittest
from argparse import Namespace
from se_profile.profile import run_profiler, MemProfiler



class MemProfilerTests(unittest.TestCase):

    def setUp(self):

        self.options = Namespace(args='', destination='./', module_name='data.make_profile_for',
                                 name='Profiler', per_file=False, print_report=False, short_name='profiler',
                                 import_limit=16, increment_limit=1, end_limit=19, peak_limit=16, debug=True)

    def tearDown(self):
        self.options = Namespace()

    @unittest.skip("Skip until we start new interpreters so we can freshly test")
    def test_with_limit_above(self):
        """Test the import limit for a script"""
        self.options.peak_limit = 20
        result = run_profiler(self.options, MemProfiler)
        self.assertTrue(result)

    def test_with_limit_below(self):
        """Test the cpu usage limit for a script"""
        self.options.peak_limit = 1
        result = run_profiler(self.options, MemProfiler)
        self.assertFalse(result)

def suite():
    suite = unittest.TestSuite()
    suite.addTests(unittest.makeSuite(MemProfilerTests, "test"))
    return suite

if __name__ == "__main__":
    unittest.main()
