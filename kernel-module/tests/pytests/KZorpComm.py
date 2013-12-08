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

import unittest
import kzorp.netlink as netlink
import kzorp.kzorp_netlink as kzorp_netlink
import testutil

class KZorpComm(unittest.TestCase):
    handle = None
    _flushables = [
                    kzorp_netlink.KZorpFlushZonesMessage,
                    kzorp_netlink.KZorpFlushServicesMessage,
                    kzorp_netlink.KZorpFlushDispatchersMessage,
                    kzorp_netlink.KZorpFlushBindsMessage
                  ]

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)
        self.create_handle()
        self._in_transaction = False

    def __del__(self):
        self.close_handle()

    def create_handle(self):
        if self.handle == None:
            self.handle = kzorp_netlink.Handle()
            self.assertNotEqual(self.handle, None)

    def close_handle(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def reopen_handle(self):
        self.close_handle()
        self.create_handle()

    def send_message(self, message, assert_on_error = True, message_handler = None, dump = False, error_handler=None):
        self.assertNotEqual(message, None)
        self.assertNotEqual(self.handle, None)

        try:
            res = 0
            for reply_message in self.handle.talk(message, dump):
                if message_handler is not None:
                    message_handler(reply_message)
                else:
                    pass
        except netlink.NetlinkException as e:
            res = e.detail
            if assert_on_error:
                if error_handler:
                    error_handler(e.detail)
                else:
                    self.assertTrue(res, "talk with KZorp failed")

        return res

    def start_transaction(self, instance_name = kzorp_netlink.KZ_INSTANCE_GLOBAL, cookie = 0L):
        self.send_message(kzorp_netlink.KZorpStartTransactionMessage(instance_name))
        self._in_transaction = True

    def end_transaction(self, instance_name = kzorp_netlink.KZ_INSTANCE_GLOBAL):
        self.send_message(kzorp_netlink.KZorpCommitTransactionMessage())
        self._in_transaction = False

    def flush_all(self):
        if self._in_transaction:
            self.reopen_handle()
            self._in_transaction = False

        for message_class in self._flushables:
            self.start_transaction()
            self.send_message(message_class())
            self.end_transaction()

    def test_handle(self):
      self.create_handle()
      self.start_transaction()
      self.end_transaction()
      self.flush_all()
      self.reopen_handle()


if __name__ == "__main__":
    testutil.main()
