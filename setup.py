#!/usr/bin/env python
# coding=utf-8

"""

PasswordMaker - Python library
==============================

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


from distutils.core import setup, Command
import sys
import subprocess


class PyTest(Command):
    """Class for running py.test via setup.py"""

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        errno = subprocess.call([sys.executable, 'testpwmlib.py'])
        raise SystemExit(errno)


setup(
    name='PasswordMaker - Python',
    version='0.0.1',
    description='Create and manage passwords.',
    long_description='PasswordMaker - Python is a Python implementation of' +\
                     'PasswordMaker (see https://passwordmaker.org).' +\
                     'Its objective is to generate Web-site individual ' +\
                     'passwords from hashes of the site url and a master ' +\
                     'password.',
    license='GPL v3 :: GNU General Public License',
    keywords=['PasswordMaker'],
    requires=['attrs (>=17.0)'],
    packages=['.'],
    scripts=['passwordmaker.py'],
    cmdclass={'test': PyTest},
    package_data={
        'passwordmaker': [
            '*.py',
            'COPYING',
            'COPYING.LESSER',
            'README.md',
            'todo.txt',
        ],
    },
    classifiers=[
        'Development Status :: 2 - Pre-Alpha  ',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
    ],
)
