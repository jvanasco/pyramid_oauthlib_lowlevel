"""pyramid_oauthlib_lowlevel installation script.
"""
import os
import re

from setuptools import find_packages
from setuptools import setup

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = description = "lowlevel Pyramid implementation of oauthlib"
with open(os.path.join(HERE, "README.md")) as fp:
    long_description = fp.read()

# store version in the init.py
with open(
    os.path.join(HERE, "src", "pyramid_oauthlib_lowlevel", "__init__.py")
) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)

requires = [
    "oauthlib",
    "pyramid",
    "requests_oauthlib",
    "requests",
]
tests_require = [
    "pyramid_formencode_classic",
    "pyramid_mako",
    "pyramid_tm",
    "pyramid",
    "pytest",
    "responses",
    "sqlalchemy",
    "webtest",
    "zope.sqlalchemy",
]
testing_extras = tests_require + []


setup(
    name="pyramid_oauthlib_lowlevel",
    version=VERSION,
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    url="https://github.com/jvanasco/pyramid_oauthlib_lowlevel",
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Intended Audience :: Developers",
        "Framework :: Pyramid",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: BSD License",
    ],
    keywords="web pyramid oauth oauthlib",
    py_modules=["pyramid_oauthlib_lowlevel"],
    license="BSD",
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    package_data={"pyramid_oauthlib_lowlevel": ["py.typed"]},
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    test_suite="tests",
)
