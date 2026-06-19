# Benign decoy fixture. Ordinary C-extension build; no env access, no network.
from setuptools import setup, Extension

setup(
    name="fastmath-ext",
    version="0.4.0",
    description="Small fast math helpers as a C extension",
    ext_modules=[Extension("fastmath_ext", sources=["fastmath.c"])],
)
