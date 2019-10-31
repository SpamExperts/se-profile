import sys
import unittest
import traceback

def usuite():
    test_suite = unittest.TestSuite()

    from tests import test_se_profile

    test_suite.addTest(test_se_profile.suite())

    return test_suite

def fsuite():
    pass

def suite():
    test_suite = unittest.TestSuite()
    test_suite.addTest(fsuite())
    test_suite.addTest(usuite())
    return test_suite

if __name__ == "__main__":
    try:
        unittest.main(defaultTest="suite")
    except:
        traceback.print_exc(file=sys.__stderr__)
