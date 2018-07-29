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

import sys
import hmac
import json
import attr

from math import ceil, log

try:
    # Do we have pycrypto ? <http://www.amk.ca/python/code/crypto>
    from Crypto.Hash import MD4, SHA256, RIPEMD
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

HAS_HASHLIB = float(sys.version[:3]) >= 2.5

if HAS_HASHLIB:
    import hashlib
else:
    try:
        import sha
        import md5
    except ImportError:
        raise ImportError("No crypto library found")


class PWM_Error(Exception):
    """Password Maker Error class"""


class PWM(object):
    """Main PasswordMaker class used for generating passwords"""

    FULL_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + \
                   "0123456789`~!@#$%^&*()_-+={}|[]\\:\";\'<>?,./"

    _ALGORITHMS = ["md5", "hmac-md5", "sha1", "hmac-sha1"]
    if HAS_HASHLIB:
        _ALGORITHMS += ["sha256", "hmac-sha256"]
    if HAS_CRYPTO:
        _ALGORITHMS += ["md4", "hmac-md4", "sha256", "hmac-sha256", "rmd160",
                        "hmac-rmd160"]
    ALGORITHMS = tuple(set(_ALGORITHMS))

    def generatepasswordfrom(self, settings):
        concat_url = settings.URL + settings.Username + settings.Modifier
        return self.generatepassword(settings.Algorithm,
                                     settings.MasterPass,
                                     concat_url,
                                     settings.Length,
                                     settings.CharacterSet,
                                     settings.Prefix,
                                     settings.Suffix)

    # L33t not used here
    def generatepassword(self, hashAlgorithm, key, data, passwordLength,
                         charset, prefix="", suffix=""):
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
        algo_error_msg = "Unknown or misspelled algorithm: {}. " + \
                         "Valid algorithms: {}"
        if hashAlgorithm not in PWM.ALGORITHMS:
            valid_algs = ", ".join(PWM.ALGORITHMS)
            raise PWM_Error(algo_error_msg.format(hashAlgorithm, valid_algs))

        # apply the algorithm
        hashclass = PWM_HashUtils()
        password = ''
        count = 0

        key = key.encode("utf-8")
        data = data.encode("utf-8")

        tkey = key  # Copy of the master password so we don't interfere with it
        dat = data
        while len(password) < passwordLength and count < 1000:
            if count == 0:
                key = tkey
            else:
                key = "{}\n{}".format(tkey, count).encode("utf-8")

            # For non-hmac algorithms, the key is master pw and url
            # concatenated
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
                valid_algs = ", ".join(PWM.ALGORITHMS)
                raise PWM_Error(algo_error_msg.format(hashAlgorithm,
                                                      valid_algs))
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
        while len(dividend) < ceil(len(inp) / 2):
            dividend.append(0)

        for i in range(len(dividend)):
            try:
                dividend[i] = (inp[i * 2] << 8) | inp[i * 2 + 1]
            except TypeError:  # Python 2.x
                dividend[i] = (ord(inp[i * 2]) << 8) | ord(inp[i * 2 + 1])

        # Repeatedly perform a long division. The binary array forms the
        # dividend, the length of the encoding is the divisor. Once computed,
        # the quotient forms the dividend for the next step. We stop when the
        # dividend is zero. All remainders are stored for later use.

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
            full_length = ceil(float(len(inp) * 8) /
                               (log(len(encoding)) / log(2)))
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

        return output

    def any_md5(self, s, e, t):
        if HAS_HASHLIB:
            __hash = hashlib.md5(s).digest()
        else:
            __hash = md5.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_md5(self, k, d, e, t):
        if HAS_HASHLIB:
            hashfunc = hashlib.md5
        else:
            hashfunc = md5
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_sha1(self, s, e, t):
        if HAS_HASHLIB:
            __hash = hashlib.sha1(s).digest()
        else:
            __hash = sha.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_sha1(self, k, d, e, t):
        if HAS_HASHLIB:
            hashfunc = hashlib.sha1
        else:
            hashfunc = sha
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_sha256(self, s, e, t):
        if HAS_HASHLIB:
            __hash = hashlib.sha256(s).digest()
        else:
            __hash = SHA256.new(s).digest()
        return self.rstr2any(__hash, e, t)

    def any_hmac_sha256(self, k, d, e, t):
        if HAS_HASHLIB:
            hashfunc = hashlib.sha256
        else:
            hashfunc = SHA256
        return self.rstr2any(hmac.new(k, d, hashfunc).digest(), e, t)

    def any_md4(self, s, e, t):
        return self.rstr2any(MD4.new(s).digest(), e, t)

    def any_hmac_md4(self, k, d, e, t):
        return self.rstr2any(hmac.new(k, d, MD4).digest(), e, t)

    def any_rmd160(self, s, e, t):
        return self.rstr2any(RIPEMD.new(s).digest(), e, t)

    def any_hmac_rmd160(self, k, d, e, t):
        return self.rstr2any(hmac.new(k, d, RIPEMD).digest(), e, t)


@attr.s
class PWM_Settings(object):
    """Setting class holding all parameters for hash generation"""

    int_val = attr.validators.instance_of(int)
    str_val = attr.validators.instance_of(str)
    bool_val = attr.validators.instance_of(bool)
    algorithm_val = attr.validators.in_(PWM.ALGORITHMS)

    URL = attr.ib(default="", validator=str_val, type="str",
                  metadata={'cmd1': "-r", 'cmd2': "--url",
                            "guitext": "URL",
                            "help": "URL (default blank)"})
    MasterPass = attr.ib(default="", validator=str_val, type="pwd",
                         metadata={'cmd1': "-m", 'cmd2': "--mpw",
                                   "guitext": "Master PW",
                                   "help": "Master password (default: ask)"})
    Algorithm = attr.ib(default="md5", validator=algorithm_val, type="alg",
                        metadata={'cmd1': "-a", 'cmd2': "--alg",
                                  "guitext": "Algorithm",
                                  "help": "Hash algorithm [hmac-] " +
                                  "md4/md5/sha1/sha256/rmd160 [_v6] " +
                                  "(default md5)"})
    Username = attr.ib(default="", validator=str_val, type="str",
                       metadata={'cmd1': "-u", 'cmd2': "--user",
                                 "guitext": "Username",
                                 "help": "Username (default blank)"})
    Modifier = attr.ib(default="", validator=str_val, type="str",
                       metadata={'cmd1': "-d", 'cmd2': "--modifier",
                                 "guitext": "Modifier",
                                 "help": "Password modifier (default blank)"})
    Length = attr.ib(default=8, validator=int_val, type="int",
                     metadata={'cmd1': "-g", 'cmd2': "--length",
                               "guitext": "Length",
                               "help": "Password length (default 8)"})
    CharacterSet = attr.ib(default=str(PWM().FULL_CHARSET), validator=str_val,
                           type="str",
                           metadata={'cmd1': "-c", 'cmd2': "--charset",
                                     "guitext": "Characters",
                                     "help": "Characters to use in password " +
                                             "(default [A-Za-z0-9])"})
    Prefix = attr.ib(default="", validator=str_val, type="str",
                     metadata={'cmd1': "-p", 'cmd2': "--prefix",
                               "guitext": "Prefix",
                               "help": "Password prefix (default blank)"})
    Suffix = attr.ib(default="", validator=str_val, type="str",
                     metadata={'cmd1': "-s", 'cmd2': "--suffix",
                               "guitext": "Suffix",
                               "help": "Password suffix (default blank)"})
#    UseLeet = attr.ib(default=False, validator=bool_val, type="bool",
#                      metadata={'cmd1': "-l", 'cmd2': "--leet",
#                                "guitext": "",
#                                "help": "Not implemented (does nothing)"})
#    LeetLvl = attr.ib(default=1, validator=int_val, type="int",
#                      metadata={'cmd1': "-L", 'cmd2': "--leetlevel",
#                                "guitext": "",
#                                "help": "Not implemented (does nothing)"})

    def __getitem__(self, attr):
        return self.__getattribute__(attr)

    def _get_attr_filters(self):
        """Returns attr filters that excludes MasterPass"""

        return attr.filters.exclude(attr.fields(PWM_Settings).MasterPass)

    def load(self, filepath='pwm.settings'):
        """Loads setting from a json file"""

        with open(filepath) as infile:
            file_dict = json.load(infile)

        passwd_filter = self._get_attr_filters()
        attr_fields = attr.asdict(self, filter=passwd_filter)

        try:
            for attr_key in attr_fields:
                if attr_key in file_dict:
                    self.__setattr__(attr_key, file_dict[attr_key])
                    attr.validate(self)
        except TypeError as err:
            # If attrs are of the wrong type then roll back
            for attr_key in attr_fields:
                self.__setattr__(attr_key, attr_fields[attr_key])
            raise TypeError(err)

    def save(self, filepath='pwm.settings'):
        """Saves setting to a json file"""

        passwd_filter = self._get_attr_filters()
        attr_dict = attr.asdict(self, filter=passwd_filter)

        with open(filepath, 'w') as outfile:
            json.dump(attr_dict, outfile, sort_keys=True, indent=4)
