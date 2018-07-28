# coding: utf-8
"""
  PasswordMaker - Creates and manages passwords
  Copyright (C) 2005 Eric H. Jung and LeahScape, Inc.
  http://passwordmaker.org/
  grimholtz@yahoo.com

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or (at
  your option) any later version.

  This library is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
  for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this library; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

  Written by Miquel Burns and Eric H. Jung

  PHP version written by Pedro Gimeno Fortea
      <http://www.formauri.es/personal/pgimeno/>
  and updated by Miquel Matthew 'Fire' Burns
      <miquelfire@gmail.com>
  Ported to Python by Aurelien Bompard
      <http://aurelien.bompard.org>
  Updated by Richard Beales
      <rich@richbeales.net>

  This version should work with python > 2.3. The pycrypto module enables
  additional algorithms.

"""

import sys, hmac, math


class PWM_Error(Exception):
    """
        Password Maker Error class, inherits from Exception, currently
does nothing else
    """
    pass

class PWM:
   """
      Main PasswordMaker class used for generating passwords
   """
   FULL_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()_-+={}|[]\\:\";\'<>?,./"

   def __init__(self):
      self.valid_algs = self.getValidAlgorithms()

   def getValidAlgorithms(self):
      valid_algs = ["md5", "hmac-md5", "sha1", "hmac-sha1"]
      if float(sys.version[:3]) >= 2.5: # We have hashlib
        valid_algs.extend(["sha256", "hmac-sha256"])
      try: # Do we have pycrypto ? <http://www.amk.ca/python/code/crypto>
        import Crypto  # NOQA
        for alg in ["md4", "hmac-md4", "sha256", "hmac-sha256", "rmd160", "hmac-rmd160"]:
           if alg not in valid_algs:
              valid_algs.append(alg)
      except ImportError:
        pass
      return valid_algs

   def generatepasswordfrom(self,settings):
      return self.generatepassword(settings.Algorithm,
                              settings.MasterPass,
                              settings.URL + settings.Username + settings.Modifier,
                              settings.UseLeet,
                              settings.LeetLvl,
                              settings.Length,
                              settings.CharacterSet,
                              settings.Prefix,
                              settings.Suffix)

   # L33t not used here
   def generatepassword(self,hashAlgorithm, key, data, whereToUseL33t, l33tLevel, passwordLength, charset, prefix="", suffix=""):
      # Never *ever, ever* allow the charset's length<2 else
      # the hash algorithms will run indefinitely
      if len(charset) < 2:
          return ""
      alg = hashAlgorithm.split("_")
      if len(alg) > 1 and alg[1] == "v6":
          trim = False
          charset = '0123456789abcdef'
      else:
          trim = True
          hashAlgorithm = alg[0]
      # Check for validity of algorithm
      if hashAlgorithm not in self.valid_algs:
          raise PWM_Error("Unknown or misspelled algorithm: %s. Valid algorithms: %s" % (hashAlgorithm, ", ".join(self.valid_algs)))

      # apply the algorithm
      hashclass = PWM_HashUtils()
      password = ''
      count = 0;
      tkey = key # Copy of the master password so we don't interfere with it.
      dat = data
      while len(password) < passwordLength and count < 1000:
          if count == 0:
              key = tkey
          else:
              key = "%s\n%s" % (tkey, count)
          # for non-hmac algorithms, the key is master pw and url concatenated
          if hashAlgorithm.count("hmac") == 0:
              dat = key+data
          if hashAlgorithm == "sha256":
              password += hashclass.any_sha256(dat, charset, trim)
          elif hashAlgorithm == "hmac-sha256":
              password += hashclass.any_hmac_sha256(key, dat, charset, trim)
          elif hashAlgorithm == "sha1":
              password += hashclass.any_sha1(dat, charset, trim)
          elif hashAlgorithm == "hmac-sha1":
              password += hashclass.any_hmac_sha1(key, dat, charset, trim)
          elif hashAlgorithm == "md4":
              password += hashclass.any_md4(dat, charset, trim)
          elif hashAlgorithm == "hmac-md4":
              password += hashclass.any_hmac_md4(key, dat, charset, trim)
          elif hashAlgorithm == "md5":
              password += hashclass.any_md5(dat, charset, trim)
          elif hashAlgorithm == "hmac-md5":
              password += hashclass.any_hmac_md5(key, dat, charset, trim)
          elif hashAlgorithm == "rmd160":
              password += hashclass.any_rmd160(dat, charset, trim)
          elif hashAlgorithm == "hmac-rmd160":
              password += hashclass.any_hmac_rmd160(key, dat, charset, trim)
          else:
              raise PWM_Error("Unknown or misspelled algorithm: %s. Valid algorithms: %s" % (hashAlgorithm, ", ".join(self.valid_algs)))
          count += 1

      if prefix:
          password = prefix + password
      if suffix:
          password = password[:passwordLength-len(suffix)] + suffix
      return password[:passwordLength]




class PWM_HashUtils:
    def rstr2any(self, inp, encoding, trim=True):
        """Convert a raw string to an arbitrary string encoding.
        
        Set trim to false for keeping leading zeros
           
        """
        
        divisor = len(encoding)
        remainders = []

        # Convert to an array of 16-bit big-endian values, forming the dividend
        dividend = []
        # pad this
        while len(dividend) < math.ceil(len(inp) / 2):
            dividend.append(0)

        for i in range(len(dividend)):
            print(dividend)
            print(inp, encoding, trim)
            print(repr(chr(inp[i * 2])))
            print(chr(inp[i * 2]))
            dividend[i] = (inp[i * 2] << 8) | inp[i * 2 + 1]

        # Repeatedly perform a long division. The binary array forms the dividend,
        # the length of the encoding is the divisor. Once computed, the quotient
        # forms the dividend for the next step. We stop when the dividend is zero.
        # All remainders are stored for later use.
        if trim:
            while len(dividend) > 0:
                quotient = []
                x = 0
                for i in range(len(dividend)):
                    x = (x << 16) + dividend[i]
                    q = x // divisor
                    x -= q * divisor
                    if len(quotient) > 0 or q > 0:
                        quotient.append(q)
                remainders.append(x)
                dividend = quotient
        else:
            full_length = math.ceil(float(len(inp) * 8) / (math.log(len(encoding)) / math.log(2)))
            for j in range(len(full_length)):
             quotient = []
             x = 0
             for i in range(len(dividend)):
                 x = (x << 16) + dividend[i]
                 q = x // divisor
                 x -= q * divisor
                 if len(quotient) > 0 or q > 0:
                     quotient[len(quotient)] = q
             remainders[j] = x
             dividend = quotient

        # Convert the remainders to the output string
        output = ""
        for i in reversed(remainders):
            output += encoding[i]

        print(inp, encoding, trim, output)

        return output

    def any_md5(self, s, e, t):
        s = s.encode("utf-8")
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            __hash = hashlib.md5(s).digest()
        else:
            import md5
            __hash = md5.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_md5(self, k, d, e, t):
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            hashfunc = hashlib.md5
        else:
            import md5
            hashfunc = md5
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_sha1(self, s, e, t):
        s = s.encode("utf-8")
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            __hash = hashlib.sha1(s).digest()
        else:
            import sha
            __hash = sha.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_sha1(self, k, d, e, t):
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            hashfunc = hashlib.sha1
        else:
            import sha
            hashfunc = sha
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_sha256(self, s, e, t):
        s = s.encode("utf-8")
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            __hash = hashlib.sha256(s).digest()
        else:
            from Crypto.Hash import SHA256
            __hash = SHA256.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_sha256(self, k, d, e, t):
        if float(sys.version[:3]) >= 2.5:
            import hashlib
            hashfunc = hashlib.sha256
        else:
            import Crypto.Hash.SHA256
            hashfunc = Crypto.Hash.SHA256
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_md4(self, s, e, t):
        s = s.encode("utf-8")
        from Crypto.Hash import MD4
        return self.rstr2any(MD4.new(s).digest(), e, t)

    def any_hmac_md4(self, k, d, e, t):
        import Crypto.Hash.MD4
        return self.rstr2any(hmac.new(k, d, Crypto.Hash.MD4).digest(), e, t)

    def any_rmd160(self, s, e, t):
        s = s.encode("utf-8")
        from Crypto.Hash import RIPEMD
        return self.rstr2any(RIPEMD.new(s).digest(), e, t)

    def any_hmac_rmd160(self, k, d, e, t):
        import Crypto.Hash.RIPEMD
        return self.rstr2any(hmac.new(k, d, Crypto.Hash.RIPEMD).digest(), e, t)

class PWM_Settings:
    def __init__(self):
        self.URL = ""
        self.MasterPass = "" # don't really want to save this
        self.Algorithm = "md5"
        self.Username = ""
        self.Modifier = ""
        self.Length = 8
        self.CharacterSet = PWM().FULL_CHARSET
        self.Prefix = ""
        self.Suffix = ""
        self.UseLeet = False
        self.LeetLvl = 1

    def __str__(self):
        return "URL=%s\nPWD=%s\nAlg=%s\nUsr=%s\nMod=%s\nLen=%s\nChr=%s\nPfx=%s\nSfx=%s\nL3t=%s\nLvl=%s\n" % (
            self.URL,
            self.MasterPass,
            self.Algorithm,
            self.Username,
            self.Modifier,
            self.Length,
            self.CharacterSet,
            self.Prefix,
            self.Suffix,
            self.UseLeet,
            self.LeetLvl,
            )


    def load(self):
        import os
        if os.path.exists('pwm.settings'):
            import pickle
            f = open('pwm.settings','rb')
            settings = pickle.load(f)
            f.close()
            return settings
        return PWM_Settings()

    def save(self):
        import pickle
        f = open('pwm.settings','wb')
        pickle.dump(self,f)
        f.close()
