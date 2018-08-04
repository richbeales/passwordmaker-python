#!/usr/bin/env python
# coding=utf-8

"""

PasswordMaker library
=====================

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

import os
import sys
import hmac
import json
from math import ceil, log

import attr

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

FULL_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + \
               "0123456789`~!@#$%^&*()_-+={}|[]\\:\";\'<>?,./"

# ALGORITHMS tells, which algorithms are available on the current platform.
# This depends on the Python version, i.e. if hashlib is available and on
# the availablity of pycrypto.

ALGORITHM_2_HASH_FUNC = {
    "md5": "any_md5",
    "hmac-md5": "any_hmac_md5",
    "sha1": "any_sha1",
    "hmac-sha1": "any_hmac_sha1",
}

HASHLIB_ALGORITHM_2_HASH_FUNC = {
    "sha256": "any_sha256",
    "hmac-sha256": "any_hmac_sha1",
}

CRYPTO_ALGORITHM_2_HASH_FUNC = {
    "md4": "any_md4",
    "hmac-md4": "any_hmac_md4",
    "sha256": "any_sha256",
    "hmac-sha256": "any_hmac_sha256",
    "rmd160": "any_rmd160",
    "hmac-rmd160": "any_hmac_rmd160",
}

if HAS_HASHLIB:
    ALGORITHM_2_HASH_FUNC.update(HASHLIB_ALGORITHM_2_HASH_FUNC)

if HAS_CRYPTO:
    ALGORITHM_2_HASH_FUNC.update(CRYPTO_ALGORITHM_2_HASH_FUNC)

ALGORITHMS = tuple(ALGORITHM_2_HASH_FUNC.keys())


@attr.s
class PwmHashUtils(object):
    """Provides hash functions for the passwordmaker main class

    Parameters
    ----------

    * algorithm: String
    \tOne valid algorithm out of "md5", "hmac-md5", "sha1", "hmac-sha1"
    \tIf hashlib is present also out of "sha256", "hmac-sha256"
    \tIf pycrypto is present also out of "md4", "hmac-md4", "sha256",
    \t"hmac-sha256", "rmd160", "hmac-rmd160"
    * encoding: String
    \tCharacters that may appear in the generated password

    """

    algorithm = attr.ib()
    encoding = attr.ib()

    @algorithm.validator
    def _check_algorithm(self, _, value):
        if value not in ALGORITHMS:
            msg = "Unknown algorithm: {}. Valid algorithms: {}"
            valid_algs = ", ".join(ALGORITHMS)
            raise ValueError(msg.format(value, valid_algs))

    @property
    def hash_func_wrapper(self):
        hash_func_name = ALGORITHM_2_HASH_FUNC[self.algorithm]
        return getattr(self, hash_func_name)

    def rstr2any(self, inp, trim=True):
        """Convert a raw string to encoded string

        Set trim to false for keeping leading zeros.
        The generated string only contains characters from self.charset.

        """

        encoding = self.encoding
        divisor = len(encoding)

        def get_quotient_remainder(dividend):
            """Returns tuple (quotient, remainder) from dividend"""

            quotient = []
            remainder = 0
            for dividend_ele in dividend:
                remainder = (remainder << 16) + dividend_ele
                quot = remainder // divisor
                remainder -= quot * divisor
                if quotient or quot:
                    quotient.append(quot)

            return quotient, remainder

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
            while dividend:
                dividend, remainder = get_quotient_remainder(dividend)
                remainders.append(remainder)

        else:
            full_length = ceil(float(len(inp) * 8) /
                               (log(len(encoding)) / log(2)))
            for j in range(len(full_length)):
                dividend, remainder = get_quotient_remainder(dividend)
                remainders[j] = remainder

        # Convert the remainders to the output string
        output = ""
        for i in reversed(remainders):
            output += encoding[i]

        return output

    def any_md5(self, inp, trim=True):
        """MD5 function wrapper"""

        if HAS_HASHLIB:
            __hash = hashlib.md5(inp).digest()
        else:
            __hash = md5.new(inp).digest()
        return self.rstr2any(__hash, trim)

    def any_hmac_md5(self, key, inp, trim=True):
        """MD5 HMAC function wrapper"""

        if HAS_HASHLIB:
            hashfunc = hashlib.md5
        else:
            hashfunc = md5
        return self.rstr2any(hmac.new(key, inp, hashfunc).digest(), trim)

    def any_sha1(self, inp, trim=True):
        """SHA1 function wrapper"""

        if HAS_HASHLIB:
            __hash = hashlib.sha1(inp).digest()
        else:
            __hash = sha.new(inp).digest()
        return self.rstr2any(__hash, trim)

    def any_hmac_sha1(self, key, inp, trim=True):
        """SHA1 HMAC function wrapper"""

        if HAS_HASHLIB:
            hashfunc = hashlib.sha1
        else:
            hashfunc = sha
        return self.rstr2any(hmac.new(key, inp, hashfunc).digest(), trim)

    def any_sha256(self, inp, trim=True):
        """SHA256 function wrapper"""

        if HAS_HASHLIB:
            __hash = hashlib.sha256(inp).digest()
        else:
            __hash = SHA256.new(inp).digest()
        return self.rstr2any(__hash, trim)

    def any_hmac_sha256(self, key, inp, trim=True):
        """SHA256 HMAC function wrapper"""

        if HAS_HASHLIB:
            hashfunc = hashlib.sha256
        else:
            hashfunc = SHA256
        return self.rstr2any(hmac.new(key, inp, hashfunc).digest(), trim)

    def any_md4(self, inp, trim=True):
        """MD4 function wrapper"""

        return self.rstr2any(MD4.new(inp).digest(), trim)

    def any_hmac_md4(self, key, inp, trim=True):
        """MD4 HMAC function wrapper"""

        return self.rstr2any(hmac.new(key, inp, MD4).digest(), trim)

    def any_rmd160(self, inp, trim=True):
        """RMD160 function wrapper"""

        return self.rstr2any(RIPEMD.new(inp).digest(), trim)

    def any_hmac_rmd160(self, key, inp, trim=True):
        """RMD160 HMAC function wrapper"""

        return self.rstr2any(hmac.new(key, inp, RIPEMD).digest(), trim)


@attr.s
class PwmSettings(object):
    """Setting class holding all parameters for hash generation"""

    int_val = attr.validators.instance_of(int)
    str_val = attr.validators.instance_of(str)
    bool_val = attr.validators.instance_of(bool)
    algorithm_val = attr.validators.in_(ALGORITHMS)

    _url_metadata = {'cmd1': "-r", 'cmd2': "--url", "guitext": "URL",
                     "help": "URL (default blank)"}
    URL = attr.ib(default="", validator=str_val, type="str",
                  metadata=_url_metadata)

    _mpw_metadata = {'cmd1': "-m", 'cmd2': "--mpw", "guitext": "Master PW",
                     "help": "Master password (default: ask)"}
    MasterPass = attr.ib(default="", validator=str_val, type="pwd",
                         metadata=_mpw_metadata)

    _alg_metadata = {'cmd1': "-a", 'cmd2': "--alg", "guitext": "Algorithm",
                     "help": "Hash algorithm [hmac-] md4/md5/sha1/sha256/"
                             "rmd160 (default md5)"}
    Algorithm = attr.ib(default="md5", validator=algorithm_val, type="alg",
                        metadata=_alg_metadata)

    _usr_metadata = {'cmd1': "-u", 'cmd2': "--user", "guitext": "Username",
                     "help": "Username (default blank)"}
    Username = attr.ib(default="", validator=str_val, type="str",
                       metadata=_usr_metadata)

    _mod_metadata = {'cmd1': "-d", 'cmd2': "--modifier", "guitext": "Modifier",
                     "help": "Password modifier (default blank)"}
    Modifier = attr.ib(default="", validator=str_val, type="str",
                       metadata=_mod_metadata)

    _len_metadata = {'cmd1': "-g", 'cmd2': "--length", "guitext": "Length",
                     "help": "Password length (default 8)"}
    Length = attr.ib(default=8, validator=int_val, type="int",
                     metadata=_len_metadata)

    _chr_metadata = {'cmd1': "-c", 'cmd2': "--charset",
                     "guitext": "Characters",
                     "help": "Characters to use in password (default "
                             "[A-Za-z0-9])"}
    CharacterSet = attr.ib(default=str(FULL_CHARSET), validator=str_val,
                           type="str", metadata=_chr_metadata)

    _pfx_metadata = {'cmd1': "-p", 'cmd2': "--prefix", "guitext": "Prefix",
                     "help": "Password prefix (default blank)"}
    Prefix = attr.ib(default="", validator=str_val, type="str",
                     metadata=_pfx_metadata)

    _sfx_metadata = {'cmd1': "-s", 'cmd2': "--suffix", "guitext": "Suffix",
                     "help": "Password suffix (default blank)"}
    Suffix = attr.ib(default="", validator=str_val, type="str",
                     metadata=_sfx_metadata)

#    _useleet_metadata = {'cmd1': "-l", 'cmd2': "--leet", "guitext": "",
#                         "help": "Not implemented (does nothing)"}
#    UseLeet = attr.ib(default=False, validator=bool_val, type="bool",
#                      metadata=_useleet_metadata)

#    _leetlvl_metadata = {'cmd1': "-L", 'cmd2': "--leetlevel", "guitext": "",
#                         "help": "Not implemented (does nothing)"}
#    LeetLvl = attr.ib(default=1, validator=int_val, type="int",
#                      metadata=_leetlvl_metadata)

    def __getitem__(self, __attr):
        return self.__getattribute__(__attr)

    def _get_attr_filters(self):
        """Returns attr filters that excludes MasterPass"""

        return attr.filters.exclude(attr.fields(PwmSettings).MasterPass)

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
                    try:
                        attr.validate(self)
                    except TypeError:
                        # Python 2 fix
                        value = file_dict[attr_key].encode("utf-8")
                        self.__setattr__(attr_key, value)
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


@attr.s
class PwmSettingsList(object):
    """Stores a list of PwmSettings"""

    current = attr.ib(default="default")
    pwm_names = attr.ib(default=["default"])
    pwms = attr.ib(default=[PwmSettings()])

    def get_pwm_settings(self):
        """Returns current PwmSettings"""

        pwm_idx = self.pwm_names.index(self.current)
        return self.pwms[pwm_idx]

    def load(self, directory="."):
        """Loads all PWM_setting files from current directory"""

        filenames = [f for f in os.listdir(directory)
                     if f.endswith(".setting")]
        filenames.sort()
        pwm_names = [f[4:-8] for f in filenames]

        self.pwm_names = []
        self.pwms = []
        for pwm_name, filename in zip(pwm_names, filenames):
            pwm = PwmSettings()
            pwm.load(filename)

            if pwm_name == "default":
                self.pwm_names.insert(0, pwm_name)
                self.pwms.insert(0, pwm)
            else:
                self.pwm_names.append(pwm_name)
                self.pwms.append(pwm)
        if "default" in pwm_names:
            self.current = "default"
        else:
            self.current = self.pwm_names[0]

    def save(self, directory="."):
        """Saves all PWM_setting files from current directory"""

        for name, pwm in zip(self.pwm_names, self.pwms):
            pwm.save(filepath="pwm."+name+".setting")

        filenames = [f for f in os.listdir(directory)
                     if f.endswith(".setting")]
        pwm_names = [f[4:-8] for f in filenames]

        for pwm_name in pwm_names:
            if pwm_name not in self.pwm_names:
                os.remove("pwm."+pwm_name+".setting")


# Main PasswordMaker functions


def generatepasswordfrom(settings):
    """Calls self.generatepassword with parameters from settings

    Parameters
    ----------

    * settings: PwmSettingsList
    \tSettings instance

    """

    concat_url = settings.URL + settings.Username + settings.Modifier
    return generatepassword(hash_algorithm=settings.Algorithm,
                            key=settings.MasterPass,
                            data=concat_url,
                            password_length=settings.Length,
                            charset=settings.CharacterSet,
                            prefix=settings.Prefix,
                            suffix=settings.Suffix)


def generatepassword(hash_algorithm, key, data, password_length, charset,
                     prefix="", suffix=""):
    """Generates PasswordMaker password

    Note: L33t ist not supported, yet.

    Parameters
    ----------

    * hash_algorithm: String
    \tHash algorithm from ALGORITHMS
    * key: String
    \tPassword key, normally maps from master password(!)
    * data: String
    \tBase data string, normally concatenates url, username and modifier
    * password_length: Integer
    \tLength of the generated password, must be in range(2, 129)
    * charset: String
    \tCharacters that may appear in the generated password
    * prefix: String (default: "")
    \tPassword prefix
    * suffix: String (default: "")
    \tPassword suffix

    """

    # If the charset's length < 2 the hash algorithms will run indefinitely.

    if len(charset) < 2:
        msg = "The charset {} contains less than 2 characters."
        raise ValueError(msg.format(charset))

    # apply the algorithm
    hash_func_wrapper = PwmHashUtils(hash_algorithm, charset).hash_func_wrapper
    hash_uses_hmac = hash_algorithm.count("hmac") > 0

    key = key.encode("utf-8")
    data = data.encode("utf-8")

    tkey = key  # Copy of the master password so we don't interfere with it
    dat = data

    password = ''

    for i in range(1000):
        if i:
            key = tkey + b"\n" + str(i).encode("utf-8")

        # For non-hmac algorithms, the key is master pw and url
        # concatenated

        if hash_uses_hmac:
            password += hash_func_wrapper(key, dat)
        else:
            dat = key + data
            password += hash_func_wrapper(dat)

        if len(password) >= password_length:
            break

    if prefix:
        password = prefix + password
    if suffix:
        password = password[:password_length-len(suffix)] + suffix

    return password[:password_length]
