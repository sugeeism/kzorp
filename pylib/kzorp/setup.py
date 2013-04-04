#!/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import sys, os

srcdir = os.path.dirname(sys.path[0])

setup(
  package_dir = { 'kzorp': os.path.join(srcdir, 'kzorp/kzorp') },
  name="python-kzorp",
  description="Kzorp bindings for python",
  author="Krisztián Kovács",
  author_email="hidden@balabit.hu",
  packages=["kzorp"]
  )
