#!/usr/bin/env python
#
# Copyright (C) 2006-2012, BalaBit IT Ltd.
# This program/include file is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2 of the License, or
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

import os
import sys
import glob

import socket
socket.IP_TRANSPARENT = 19
socket.SO_KZORP_RESULT = 1678333

import test_kzorp
import kzorp.kzorp_netlink as kznl


class KZorpSockoptTest(test_kzorp.KZorpComm):
    def __init__(self, *args):
        super(KZorpSockoptTest, self).__init__(*args)
        self.handle = kznl.Handle()

    __setup_messages = \
        (
          KZorpAddProxyServiceMessage("service"),
          KZorpAddZoneMessage("internet"),
          KZorpAddDispatcherMessage("dispatcher", 1),
          KZorpAddRuleMessage("dispatcher", 1, "service", {}),
        )

    def setUp(self):
        self.start_transaction()
        self.flush_all()
        [self.handle.talk(m) for m in self.__setup_messages]
        self.end_transaction()

    def tearDown(self):
        self.flush_all()

if __name__ == "__main__":

    if os.getenv("USER") != "root":
        print "ERROR: You need to be root to run the unit test"
        sys.exit(1)

    if glob.glob('/var/run/zorp/*.pid'):
        print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
        print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
        print "       in order to run this test."
        sys.exit(1)

    test = KZorpSockoptTest()
    test.setUp()

    print "*" * 70
    print "KZorp configuration set up, start get_kzorp_result, then connect to"
    print "any TCP port of the test host with netcat. get_kzorp_result should"
    print "then print the following following:\n"
    print "Cookie: 123456789, client zone: 'internet', server zone: 'internet',"
    print "dispatcher: 'dispatcher', service: 'service'\n"
    print "Then press Enter to flush the KZorp configuration"
    print "*" * 70

    sys.stdin.readline()
    test.tearDown()
