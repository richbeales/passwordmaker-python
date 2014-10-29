#!/usr/bin/env python

from pwmlib import *
import unittest

class PWTest(unittest.TestCase):
    def setUp(self):
        self.pw = PWM()

    def test_generatepassword_19chars(self):
        res = self.pw.generatepassword('md5','asdf','passwordmaker.org'+''+'',False,1,19,self.pw.FULL_CHARSET,'','')
        self.assertEqual(res,'FRRHm)k+UyQiY~%Dj;h')

    def test_generatepassword_20chars(self):
        res = self.pw.generatepassword('md5','asdf','passwordmaker.org'+''+'',False,1,20,self.pw.FULL_CHARSET,'','')
        self.assertEqual(res,'FRRHm)k+UyQiY~%Dj;h*')
    def test_64chars(self):
        res = self.pw.generatepassword('md5','asdf','passwordmaker.org'+''+'',False,1,64,self.pw.FULL_CHARSET,'','')
        self.assertEqual(res,'FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5krPbfUlY7BRv12Dl.QJ=-]pF}UyDtCZ9#')
if __name__ == '__main__':
    unittest.main()
