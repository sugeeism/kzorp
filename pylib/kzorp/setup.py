#!/bin/env python
#
# Copyright (C) 2006-2012, BalaBit IT Ltd.
# This program/include file is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program/include file is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
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
