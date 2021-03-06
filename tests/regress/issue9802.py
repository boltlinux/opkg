#! /usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import os
import opk, cfg, opkgcl

opk.regress_init()

o = opk.OpkGroup()
o.add(Package="a", Depends="b")
o.add(Package="b", Version="1.0")
o.add(Package="b", Version="2.0")
o.write_opk()
o.write_list()

opkgcl.update()

opkgcl.install("b_1.0_all.opk")
if not opkgcl.is_installed("b", "1.0"):
    opk.fail("Package 'b' failed to install")

opkgcl.install("a")
if not opkgcl.is_installed("a"):
    opk.fail("Package 'a' failed to install")
if not opkgcl.is_installed("b", "1.0"):
    opk.fail("Package 'b' upgraded but upgrade was not necessary")
