#!/usr/bin/env python
# coding=utf-8

"""

PasswordMaker - Python unit tests in comparison with cli pwm tool
=================================================================

Create and manage passwords.


Copyright (C):
    2018      Martin Manns
              <mmanns@gmx.net>

    This file is part of PasswordMaker.

    PasswordMaker is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Foobar.  If not, see <https://www.gnu.org/licenses/>.

This version should work with Python > 2.3 including Python 3.x.
The pycrypto module enables additional algorithms.

It can be used both on the command-line and with a GUI based on TKinter.

"""

import unittest
import subprocess

from pwmlib import generatepassword, ALGORITHMS, FULL_CHARSET


class TestGeneratepassword(unittest.TestCase):
    """Unit test class for generatepassword"""

    # The parameters that are tested in a full factorial way
    parameter_set = {
        "hashAlgorithm": ALGORITHMS,
        "key": ["asdf", "sdfmnklk3", "21289,.3"],
        "data": ['passwordmaker.org', 'abcdefghijklmnopqrstuvwxyz.com'],
        "passwordLength": [1, 19, 64, 127],
    }

    def _gen_params(self):
        """Generator of parameters from self.parameter_set"""

        for hashAlgorithm in self.parameter_set["hashAlgorithm"]:
            for key in self.parameter_set["key"]:
                for data in self.parameter_set["data"]:
                    for passwordLength in self.parameter_set["passwordLength"]:
                        yield {
                            "hashAlgorithm": hashAlgorithm,
                            "key": key,
                            "data": data,
                            "passwordLength": passwordLength,
                            }

    def _generatepassword(self,
                          hashAlgorithm="md5",
                          key="asdf",
                          data='passwordmaker.org',
                          passwordLength=19,
                          charset=FULL_CHARSET,
                          prefix="",
                          suffix=""):
        return generatepassword(hashAlgorithm, key, data, passwordLength,
                                charset, prefix, suffix)

    def _get_cmd_args(self, params):
        """Returns command line arguments for given paramters"""

        args = ["passwordmaker"]

        halg = params["hashAlgorithm"].upper().replace("RMD160", "RIPEMD160")
        if "HMAC-" in halg:
            args.append("--HMAC")
            halg = halg[5:]
        args.append("--alg")
        args.append(halg)

        args.append("--mpw " + params["key"])
        args.append("--url " + params["data"])
        args.append("--length " + str(params["passwordLength"]))

        return args

    def test_generatepassword(self):
        """The main test

        Requires Python 3.4+

        """

        for params in self._gen_params():
            with self.subTest(params=params):
                res = self._generatepassword(**params)

                args = self._get_cmd_args(params)

                completed_proc = subprocess.run(args, stdout=subprocess.PIPE)

                __res = completed_proc.stdout.strip().decode("utf-8")
                if __res.startswith("WARNING"):
                    __res = __res.split("\n")[-1]

                self.assertEqual(res, __res)

#    def test_generatepassword_2chars(self):
#        res = self._generatepassword(passwordLength=2)
#        self.assertEqual(res, 'FR')
#
#    def test_generatepassword_19chars(self):
#        res = self._generatepassword(passwordLength=19)
#        self.assertEqual(res, 'FRRHm)k+UyQiY~%Dj;h')
#
#    def test_generatepassword_20chars(self):
#        res = self._generatepassword(passwordLength=20)
#        self.assertEqual(res, 'FRRHm)k+UyQiY~%Dj;h*')
#
#    def test_32chars(self):
#        res = self._generatepassword(passwordLength=32)
#        r = 'FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5k'
#        self.assertEqual(res, r)
#
#    def test_64chars(self):
#        res = self._generatepassword(passwordLength=64)
#        r = 'FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5krPbfUlY7BRv12Dl.QJ=-]pF}UyDtCZ9#'
#        self.assertEqual(res, r)
#
#    # Vary algorithm
#
#    def test_generatepassword_sha256(self):
#        alg = "sha256"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = '7d,Hgx:o&+&}h;=*>5r'
#        self.assertEqual(res, r)
#
#    def test_generatepassword_hmac_sha256(self):
#        alg = "hmac-sha256"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = '~A6{!<Y4UGo$%7x;alX'
#        self.assertEqual(res, r)
#
#    def test_generatepassword_sha1(self):
#        alg = "sha1"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = "D)k{Gq\\\\'7]-/3\\=m4p"
#        self.assertEqual(res, r)
#
#    def test_generatepassword_hmac_sha1(self):
#        alg = "hmac-sha1"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = "E~|ym$>s:gp'cx-}Y.|"
#        self.assertEqual(res, r)
#
#    def test_generatepassword_md4(self):
#        alg = "md4"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = 'BE?3q<(S"!(Hyr(dUmr'
#        self.assertEqual(res, r)
#
#    def test_generatepassword_hmac_md4(self):
#        alg = "hmac-md4"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = 'B^z!H_Nx\\p0=iVV<>X,'
#        self.assertEqual(res, r)
#
#    def test_generatepassword_hmac_md5(self):
#        alg = "hmac-md5"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = 'IGf<=RsU3qvE"hBFmG}'
#        self.assertEqual(res, r)
#
#    def test_generatepassword_rmd160(self):
#        alg = "rmd160"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = "CmAQg:hV'<~Vz.:NnDV"
#        self.assertEqual(res, r)
#
#    def test_generatepassword_hmac_rmd160(self):
#        alg = "hmac-rmd160"
#        if alg not in ALGORITHMS:
#            raise Warning("Algorithm {} unavailable.".format(alg))
#        res = self._generatepassword(hashAlgorithm=alg)
#        r = 'DBgLK[hHK{[e8nfH8/S'
#        self.assertEqual(res, r)
#
#    # Vary multiple parameters
#
#    def test_generatepassword_20chars_hmac(self):
#        res = self._generatepassword(hashAlgorithm="hmac-rmd160",
#                                     passwordLength=20)
#        self.assertEqual(res, 'DBgLK[hHK{[e8nfH8/SI')
#
#    def test_64chars_hmac(self):
#        res = self._generatepassword(hashAlgorithm="hmac-rmd160",
#                                     passwordLength=64)
#        r = 'DBgLK[hHK{[e8nfH8/SI.Kz.(E}10$O-U2#f{jBWYT]b:&]vjDC3bBPQE*XN)\'5y'
#        self.assertEqual(res, r)
#
#    def test_128chars(self):
#        res = self._generatepassword(passwordLength=128)
#        r = "FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5krPbfUlY7BRv12Dl.QJ=-]pF}UyDtC" +\
#            "Z9#e/Gs\\l?0QX2P*gBvHTp" + '"' + "t#h^Knv{l\'G" + r'"' + \
#            "AK-qG/DWhEk9l-c%tqH}&ttsK\\<Yl4&{"
#        self.assertEqual(res, r)
#
#
#class TestLeet(unittest.TestCase):
#    """Unit test class for leet"""
#
#    def test_leet_0(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 0
#        res = leet(leet_level, message)
#        r = "the quick, brown fox jumps over the lazy dog"
#        self.assertEqual(res, r)
#
#    def test_leet_1(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 1
#        res = leet(leet_level, message)
#        r = "7h3 9uick, br0wn f0x jumps 0v3r 7h3 14zy d0g"
#        self.assertEqual(res, r)
#
#    def test_leet_2(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 2
#        res = leet(leet_level, message)
#        r = "7h3 9ulck, br0wn f0x jump5 0v3r 7h3 142y d0g"
#        self.assertEqual(res, r)
#
#    def test_leet_3(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 3
#        res = leet(leet_level, message)
#        r = "7h3 9u'ck, 8r0wn f0x jump5 0v3r 7h3 142'/ d06"
#        self.assertEqual(res, r)
#
#    def test_leet_4(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 4
#        res = leet(leet_level, message)
#        r = "7h3 9u'ck, 8r0wn f0x jump5 0v3r 7h3 1@2'/ d06"
#        self.assertEqual(res, r)
#
#    def test_leet_5(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 5
#        res = leet(leet_level, message)
#        r = "7#3 9u!c|<, |3|20wn f0x 7um|>$ 0\/3|2 7#3 1@2'/ d06"
#        self.assertEqual(res, r)
#
#    def test_leet_6(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 6
#        res = leet(leet_level, message)
#        r = "7#& 9u!c|<, |3|20wn |=0x ,|um|>$ 0\/&|2 7#& 1@2'/ |)06"
#        self.assertEqual(res, r)
#
#    def test_leet_7(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 7
#        res = leet(leet_level, message)
#        r = "7#& 9(_)![|<, |3|20\/\/^/ |=0>< ,|(_)^^|*5 0\/&|2 7#& 1@2'/ |)06"
#        self.assertEqual(res, r)
#
#    def test_leet_8(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 8
#        res = leet(leet_level, message)
#        r = '||-|& (,)|_|!(|(, 8|2()\\^/|\\| |=())( _||_||\\/||>$ ()\\/&|2 ' +\
#            '||-|& 1@"/_\'/ |)()6'
#        self.assertEqual(res, r)
#
#    def test_leet_9(self):
#        message = "The quick, brown fox jumps over the lazy dog"
#        leet_level = 9
#        res = leet(leet_level, message)
#        r = '||-|& (,)|_|!(|{, 8|2()\\^/|\\| |=())( _||_|/\\/\\|>$ ()\\/&|2' +\
#            ' ||-|& |_@"/_\'/ |)()6'
#        self.assertEqual(res, r)


if __name__ == '__main__':
    unittest.main()
