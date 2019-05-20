"""pyramid_oauthlib_lowlevel installation script.
"""
import os
import re

from setuptools import setup
from setuptools import find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as fp:
    README = fp.read()
README = README.split('\n\n', 1)[0] + "\n"

# store version in the init.py
with open(os.path.join(os.path.dirname(__file__),
                       'pyramid_oauthlib_lowlevel',
                       '__init__.py'
                       )
          ) as v_file:
    VERSION = re.compile(
        r".*__VERSION__ = '(.*?)'",
        re.S).match(v_file.read()).group(1)
        
requires = [
    "oauthlib",
    "pyramid",
]
requires_tests = [
    'pyramid_formencode_classic',
    'pyramid_mako',
    'pyramid_tm',
    'pyramid',
    'requests_oauthlib',
    'requests',
    'responses',
    'sqlalchemy',
    'twython',
    'webtest',
    'zope.sqlalchemy',
]

setup(
    name="pyramid_oauthlib_lowlevel",
    version=VERSION,
    description="lowlevel pyramid implementation of oauthlib",
    long_description=README,
    classifiers=[
        "Intended Audience :: Developers",
        "Framework :: Pyramid",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
    ],
    keywords="web pyramid",
    py_modules=['pyramid_oauthlib_lowlevel'],
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    url="https://github.com/jvanasco/pyramid_oauthlib_lowlevel",
    license="BSD",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires = requires,
    tests_require = requires + requires_tests,
    test_suite='pyramid_oauthlib_lowlevel.tests',
)
