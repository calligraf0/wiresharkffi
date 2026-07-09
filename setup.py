"""
Minimal setup.py - exists only to pass cffi_modules to setuptools.

cffi_modules is a keyword injected by cffi's setuptools plugin
(setuptools.finalize_distribution_options entry point) and is not
a standard setuptools key, so it must come through setup().
All project metadata lives in pyproject.toml.
"""
from setuptools import setup

setup(
    cffi_modules=["src/wiresharkffi/_ws_build.py:ffi"],
)
