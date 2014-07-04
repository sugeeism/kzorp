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
import testutil
from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
import kzorp.netlink as netlink
import kzorp.kzorp_netlink as kzorp_netlink
import errno
import socket

class KZorpTestCaseZones(KZorpBaseTestCaseZones):
    _zones = [
               {'name' :  'a', 'uname' : 'root', 'pname' : None,   'address' : '10.0.100.1',     'mask' : 32, 'family' : socket.AF_INET},
               {'name' :  'b', 'uname' :    'b', 'pname' : 'root', 'address' : '10.0.102.1',     'mask' : 31, 'family' : socket.AF_INET},
               {'name' :  'c', 'uname' :    'c', 'pname' :    'b', 'address' : '10.0.103.1',     'mask' : 30, 'family' : socket.AF_INET},
               {'name' :  'd', 'uname' :    'd', 'pname' :    'b', 'address' : '10.0.104.1',     'mask' : 29, 'family' : socket.AF_INET},
               {'name' :  'e', 'uname' :    'e', 'pname' :    'b', 'address' : '10.0.105.1',     'mask' : 28, 'family' : socket.AF_INET},
               {'name' :  'f', 'uname' :    'f', 'pname' :    'b', 'address' : '10.0.106.1',     'mask' : 27, 'family' : socket.AF_INET},
               {'name' :  'g', 'uname' :    'g', 'pname' :    'f', 'address' : '10.0.107.1',     'mask' : 26, 'family' : socket.AF_INET},
               {'name' :  'h', 'uname' :    'h', 'pname' :    'g', 'address' : '10.0.108.1',     'mask' : 25, 'family' : socket.AF_INET},
               {'name' :  'i', 'uname' :    'i', 'pname' :    'g', 'address' : '10.0.109.1',     'mask' : 24, 'family' : socket.AF_INET},
               {'name' :  'j', 'uname' :    'j', 'pname' :    'g', 'address' : '10.0.110.1',     'mask' : 23, 'family' : socket.AF_INET},
               {'name' : 'a6', 'uname' :   'k6', 'pname' :   None, 'address' : 'fc00:0:101:1::', 'mask' : 64, 'family' : socket.AF_INET6},
             ]

    def newSetUp(self):
        self.start_transaction()

        for zone in self._zones:
            family = zone['family']
            add_zone_message = kzorp_netlink.KZorpAddZoneMessage(zone['name'],
                                                   family = family,
                                                   uname = zone['uname'],
                                                   pname = zone['pname'],
                                                   address = socket.inet_pton(family, zone['address']),
                                                   mask = socket.inet_pton(family, testutil.size_to_mask(family, zone['mask'])))
            self.send_message(add_zone_message)

        self.end_transaction()
        self._index = -1
        self._add_zone_message = None
        self._add_zone_messages = []

    def tearDown(self):
        self.flush_all()

    def test_add_zone(self):
        self.newSetUp()
        #set up and ter down test the zone addition
        self.check_zone_num(len(self._zones))

    def test_add_zone_errors(self):
        zones = [
                  {'name' : 'fake', 'uname' :  'x1', 'pname' :   'x', 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.ENOENT},
                  {'name' : 'fake', 'uname' :   'a',  'pname' : 'xx', 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.ENOENT},
                  {'name' : 'fake', 'uname' :   'a',  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : 0},
                  {'name' : 'fake', 'uname' :   'a',  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.EEXIST},
                  {'name' : 'fake', 'uname' :  None,  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : 0},
                  {'name' : 'fake', 'uname' :  'x2',  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : 0},
                  {'name' :    '',  'uname' :  'x3',  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
                  {'name' : 'fake', 'uname' :    '',  'pname' : None, 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
                  {'name' : 'fake', 'uname' :  None,  'pname' :   '', 'address' : None, 'mask' : None, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
                ]

        add_zone_message = kzorp_netlink.KZorpAddZoneMessage('a');
        res = self.send_message(add_zone_message, assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

        self.start_transaction()
        for zone in zones:
            mask = zone['mask']
            if mask != None:
                mask = size_to_mask(mask)

            if zone['address'] != None:
                add_zone_message = kzorp_netlink.KZorpAddZoneMessage(zone['name'],
                                                       family = zone['family'],
                                                       uname = zone['uname'],
                                                       pname = zone['pname'],
                                                       address = inet_aton(zone['address']),
                                                       mask = mask)
            else:
                add_zone_message = kzorp_netlink.KZorpAddZoneMessage(zone['name'],
                                                       family = zone['family'],
                                                       uname = zone['uname'],
                                                       pname = zone['pname'])

            res = self.send_message(add_zone_message, assert_on_error = False)
            self.assertEqual(res, zone['error'])
        self.end_transaction()

    def _get_zone_message_handler(self, msg):
        self._add_zone_message = msg
        self._index += 1

        self._check_zone_params(msg, self._zones[self._index])

    def test_get_zone_by_name(self):
        self.newSetUp()
        #get each created zone
        for zone in self._zones:
            zone_name = zone['uname']
            self.send_message(kzorp_netlink.KZorpGetZoneMessage(zone_name), message_handler = self._get_zone_message_handler)
        self.assertNotEqual(self._index, len(self._zones))

        #get a not existent zone
        self.assertNotEqual(self._zones[0]['name'], self._zones[0]['uname'])
        res = self.send_message(kzorp_netlink.KZorpGetZoneMessage(self._zones[0]['name']), assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

    def _get_zones_message_handler(self, msg):
        self._add_zone_messages.append(msg)

    def test_get_zone_with_dump(self):
        self.newSetUp()
        #get the dump of zones
        self.send_message(kzorp_netlink.KZorpGetZoneMessage(None), message_handler = self._get_zones_message_handler, dump = True)
        self.assertEqual(len(self._add_zone_messages), len(self._zones))
        for add_zone_message in self._add_zone_messages:
            for i in range(len(self._zones)):
                if self.get_zone_uname(add_zone_message) == self._zones[i]['uname']:
                    self._check_zone_params(add_zone_message, self._zones[i])
                    break
            else:
                self.assert_(True, "zone with name %s could not find in the dump" % self.get_zone_uname(add_zone_message))


if __name__ == "__main__":
    testutil.main()
