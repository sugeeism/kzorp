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
import kzorp.kzorp_netlink as kznl
import socket
import testutil
import errno
from functools import partial
from KZorpComm import KZorpComm

class KZorpTestCaseServices(KZorpComm):

    services = [
        (kznl.KZorpAddProxyServiceMessage,
         { 'name': "test-proxy" }),

        (kznl.KZorpAddForwardServiceMessage,
         { 'name': "test3", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (kznl.KZorpAddForwardServiceMessage,
         { 'name': "test6", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (kznl.KZorpAddProxyServiceMessage,
         {'name': 'test5', 'count': 303}),

        (kznl.KZorpAddDenyServiceMessage,
         {'name': 'test-deny', 'logging': True, 'count': 33, 'ipv4_settings': kznl.DenyIPv4.DROP, 'ipv6_settings': kznl.DenyIPv6.DROP}),
        ]

    def check_svc_num(self, num_svc):
        _dumped_zones = []
        self.send_message(kznl.KZorpGetServiceMessage(None), message_handler = _dumped_zones.append, dump = True)
        self.assertEqual(num_svc, len(_dumped_zones))

    def check_send(self, message, return_value):
        self.start_transaction()
        r = self.send_message(message, assert_on_error=False)
        self.end_transaction()
        self.assertEqual(return_value, r)

    def newSetUp(self):
        self.start_transaction()
        for service in self.services:
            self.send_message(service[0](**service[1]))
        self.end_transaction()

    def tearDown(self):
        self.flush_all();

    def test_get_service(self):
        def check_get_reply(self, service, reply):
            for (name, value) in service[1].items():
                self.assertEqual(getattr(reply, name), value)

        self.newSetUp()
        self.check_svc_num(len(self.services))
        self.assertEqual(-2, self.send_message(kznl.KZorpGetServiceMessage("nonexistent"), assert_on_error=False))

        for service in self.services:
            self.send_message(kznl.KZorpGetServiceMessage(service[1].get('name')), message_handler = partial(check_get_reply, self, service))

    def test_add_service_duplicated(self):
        self.newSetUp()
        service_cnt = len(self.services)
        #duplicated entry check: the matching service was in the same transaction
        self.start_transaction()
        self.send_message(kznl.KZorpAddProxyServiceMessage("dupe1"))
        res = self.send_message(kznl.KZorpAddProxyServiceMessage("dupe1"), assert_on_error=False)
        self.end_transaction()
        self.assertEqual(-errno.EEXIST, res)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        #duplicated entry check: the matching service was already existing
        self.check_send(kznl.KZorpAddProxyServiceMessage("dupe1"), -errno.EEXIST)
        self.check_svc_num(service_cnt)

    def test_add_service_invalid(self):

        class KZorpAddInvalidServiceMessage(kznl.KZorpAddServiceMessage):
            type_string = "Invalid"

            def __init__(self, name):
                super(KZorpAddInvalidServiceMessage, self).__init__(name, kznl.KZ_SVC_PROXY + 100, 0, 0)

                self._build_payload()

        self.newSetUp()
        service_cnt = len(self.services)
        #invalid service type
        self.check_send(KZorpAddInvalidServiceMessage("invalid_service_type"), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def test_add_service(self):

        self.newSetUp()
        service_cnt = len(self.services)

        #outside of transaction
        self.assertEqual(-errno.ENOENT, self.send_message(self.services[0][0](**self.services[0][1]), assert_on_error=False))
        self.check_svc_num(service_cnt)

    def test_add_service_flags(self):
        self.newSetUp()
        service_cnt = len(self.services)

        for i in range(2 * kznl.KZF_SVC_LOGGING):
            self.check_send(kznl.KZorpAddProxyServiceMessage("flag-%d" % i, i), 0)

        service_cnt += 2 * kznl.KZF_SVC_LOGGING
        self.check_svc_num(service_cnt)

        # using undefined flags
        self.start_transaction()
        res = self.send_message(kznl.KZorpAddProxyServiceMessage("flag-invalid", flags=0xfffffffc), assert_on_error=False)
        self.end_transaction()
        self.assertNotEqual(0, res)

    def test_add_service_nontransparent(self):
        self.newSetUp()
        service_cnt = len(self.services)
        self.check_send(kznl.KZorpAddForwardServiceMessage("test-nontransparent-router", flags=0, count=0, dst_family=socket.AF_INET, dst_ip=socket.inet_pton(socket.AF_INET, '1.2.3.4'), dst_port=10010), 0)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        self.check_send(kznl.KZorpAddForwardServiceMessage("test-nontransparent-norouter", flags=0, count=0), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def _test_add_service_nat(self, nat_message_class):
        service_cnt = len(self.services)

        #adding a nat rule to a service added in the same transaction
        self.start_transaction()
        self.send_message(kznl.KZorpAddForwardServiceMessage('test-nat', flags=kznl.KZF_SVC_TRANSPARENT))
        self.send_message(nat_message_class('test-nat',
                                            nat_src=(kznl.KZ_SVC_NAT_MAP_IPS + kznl.KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025),
                                            nat_map=(kznl.KZ_SVC_NAT_MAP_IPS + kznl.KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025)))
        self.end_transaction()
        service_cnt += 2

        self.check_svc_num(service_cnt)

    def test_add_service_nat_dst(self):
        self.newSetUp()
        self._test_add_service_nat(kznl.KZorpAddServiceDestinationNATMappingMessage)

    def test_add_service_nat_src(self):
        self.newSetUp()
        self._test_add_service_nat(kznl.KZorpAddServiceSourceNATMappingMessage)

    def test_add_deny_service(self):
        response = []
        m = kznl.KZorpAddDenyServiceMessage("denyservice", False, 0, kznl.DenyIPv4.DROP, kznl.DenyIPv6.DROP)
        self.start_transaction()
        self.send_message(m)
        self.end_transaction()
        self.start_transaction()
        self.send_message(kznl.KZorpGetServiceMessage("denyservice"), message_handler = response.append, dump = True)
        self.end_transaction()

        self.assertEqual(1, len(response))

if __name__ == "__main__":
    testutil.main()
