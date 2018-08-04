#!/usr/bin/env python
# coding=utf-8

"""

PasswordMaker - Python unit tests
=================================

Create and manage passwords.


Copyright (C):

    2005      Eric H. Jung, Miquel Burns and LeahScape, Inc.
              <http://passwordmaker.org>
              <grimholtz@yahoo.com>
    2005-2007 Pedro Gimeno Fortea and Miquel Matthew 'Fire' Burns
              <http://www.formauri.es/personal/pgimeno/>
              <miquelfire@gmail.com>
    2010      Aurelien Bompard
              <http://aurelien.bompard.org>
    2012      Richard Beales
              <rich@richbeales.net>
    2014      Richard Beales, Laurent Bachelier and Christoph Sarnowski
              <rich@richbeales.net>
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

from pwmlib import generatepassword, ALGORITHMS, FULL_CHARSET
import unittest


class PWMTest(unittest.TestCase):
    """Unit test class for PWM"""

    def _generatepassword(self,
                          hashAlgorithm="md5",
                          key="asdf",
                          data='passwordmaker.org'+''+'',
                          passwordLength=19,
                          charset=FULL_CHARSET,
                          prefix="",
                          suffix=""):
        return generatepassword(hashAlgorithm, key, data, passwordLength,
                                charset, prefix, suffix)

    # Vary password length

    def test_generatepassword_1char(self):
        res = self._generatepassword(passwordLength=1)
        self.assertEqual(res, 'F')

    def test_generatepassword_2chars(self):
        res = self._generatepassword(passwordLength=2)
        self.assertEqual(res, 'FR')

    def test_generatepassword_19chars(self):
        res = self._generatepassword(passwordLength=19)
        self.assertEqual(res, 'FRRHm)k+UyQiY~%Dj;h')

    def test_generatepassword_20chars(self):
        res = self._generatepassword(passwordLength=20)
        self.assertEqual(res, 'FRRHm)k+UyQiY~%Dj;h*')

    def test_32chars(self):
        res = self._generatepassword(passwordLength=32)
        r = 'FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5k'
        self.assertEqual(res, r)

    def test_64chars(self):
        res = self._generatepassword(passwordLength=64)
        r = 'FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5krPbfUlY7BRv12Dl.QJ=-]pF}UyDtCZ9#'
        self.assertEqual(res, r)

    # Vary algorithm

    def test_generatepassword_sha256(self):
        alg = "sha256"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = '7d,Hgx:o&+&}h;=*>5r'
        self.assertEqual(res, r)

    def test_generatepassword_hmac_sha256(self):
        alg = "hmac-sha256"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = '~A6{!<Y4UGo$%7x;alX'
        self.assertEqual(res, r)

    def test_generatepassword_sha1(self):
        alg = "sha1"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = "D)k{Gq\\\\'7]-/3\\=m4p"
        self.assertEqual(res, r)

    def test_generatepassword_hmac_sha1(self):
        alg = "hmac-sha1"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = "E~|ym$>s:gp'cx-}Y.|"
        self.assertEqual(res, r)

    def test_generatepassword_md4(self):
        alg = "md4"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = 'BE?3q<(S"!(Hyr(dUmr'
        self.assertEqual(res, r)

    def test_generatepassword_hmac_md4(self):
        alg = "hmac-md4"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = 'B^z!H_Nx\\p0=iVV<>X,'
        self.assertEqual(res, r)

    def test_generatepassword_hmac_md5(self):
        alg = "hmac-md5"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = 'IGf<=RsU3qvE"hBFmG}'
        self.assertEqual(res, r)

    def test_generatepassword_rmd160(self):
        alg = "rmd160"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = "CmAQg:hV'<~Vz.:NnDV"
        self.assertEqual(res, r)

    def test_generatepassword_hmac_rmd160(self):
        alg = "hmac-rmd160"
        if alg not in ALGORITHMS:
            raise Warning("Algorithm {} unavailable.".format(alg))
        res = self._generatepassword(hashAlgorithm=alg)
        r = 'DBgLK[hHK{[e8nfH8/S'
        self.assertEqual(res, r)

    # Vary multiple parameters

    def test_generatepassword_20chars_hmac(self):
        res = self._generatepassword(hashAlgorithm="hmac-rmd160",
                                     passwordLength=20)
        self.assertEqual(res, 'DBgLK[hHK{[e8nfH8/SI')

    def test_64chars_hmac(self):
        res = self._generatepassword(hashAlgorithm="hmac-rmd160",
                                     passwordLength=64)
        r = 'DBgLK[hHK{[e8nfH8/SI.Kz.(E}10$O-U2#f{jBWYT]b:&]vjDC3bBPQE*XN)\'5y'
        self.assertEqual(res, r)

    def test_128chars(self):
        res = self._generatepassword(passwordLength=128)
        r = "FRRHm)k+UyQiY~%Dj;h*FV[{:5X@EN5krPbfUlY7BRv12Dl.QJ=-]pF}UyDtC" +\
            "Z9#e/Gs\\l?0QX2P*gBvHTp" + '"' + "t#h^Knv{l\'G" + r'"' + \
            "AK-qG/DWhEk9l-c%tqH}&ttsK\\<Yl4&{"
        self.assertEqual(res, r)


if __name__ == '__main__':
    unittest.main()
