import testutil
from KZorpComm import KZorpComm

import kzorp.kzorp_netlink as kznl
import socket

class KZorpBaseTestCaseBind(KZorpComm):

    _bind_addrs = [
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_UDP },
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.2'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::1'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::2'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                    { 'instance' : kznl.KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50081, 'proto' : socket.IPPROTO_TCP },
                  ]
    _dumped_bind_addrs = []

    _dumped_binds = []

    def setUp(self):
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = kznl.KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)
        self.end_transaction()

    def tearDown(self):
        self.flush_all()

    def test_unicity_check_at_transaction(self):
        self.flush_all()
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = kznl.KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)

            try:
                msg_add_bind = kznl.KZorpAddBindMessage(**bind_addr)
                self.send_message(msg_add_bind)
            except AssertionError as e:
                if e.args[0] != "talk with KZorp failed: result='-17' error='File exists'":
                    raise e

        self.end_transaction()

    def test_unicity_check_at_instance(self):
        self.flush_all()
        self.start_transaction()
        for bind_addr in self._bind_addrs:
            msg_add_bind = kznl.KZorpAddBindMessage(**bind_addr)
            self.send_message(msg_add_bind)

        for bind_addr in self._bind_addrs:
            try:
                msg_add_bind = kznl.KZorpAddBindMessage(**bind_addr)
                self.send_message(msg_add_bind)
            except AssertionError as e:
                if e.args[0] != "talk with KZorp failed: result='-17' error='File exists'":
                    raise e

        self.end_transaction()

    def _dump_bind_handler(self, message):
        self._dumped_binds.append(message)

    def get_bind(self):
        msg_get_bind = kznl.KZorpGetBindMessage()
        self.send_message(msg_get_bind, message_handler = self._dump_bind_handler, dump = True)

    def test_flush(self):
        self.flush_all()

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), 0, "bind list not empty after flush; bind_num='%d'" % len(self._dumped_binds))

    def test_add(self):
        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))

        for i in range(len(self._bind_addrs)):
            msg_add_bind = kznl.KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

    def test_auto_flush(self):
        bind_addr_num = len(self._bind_addrs)
        self._dumped_binds = []
        self.get_bind()

        # check binds set up with the original handle
        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
        for i in range(bind_addr_num):
            msg_add_bind = kznl.KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

        # set up a new set of binds with a new handle
        orig_handle = self.handle
        self.handle = None
        self.create_handle()

        for bind_addr in self._bind_addrs:
            bind_addr["port"] += 1000

        self.setUp()

        for bind_addr in self._bind_addrs:
            bind_addr["port"] -= 1000

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs) * 2)

        # close new handle and check if only the binds of the original handle remain
        self.close_handle()
        self.handle = orig_handle

        self._dumped_binds = []
        self.get_bind()

        self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
        for i in range(bind_addr_num):
            msg_add_bind = kznl.KZorpAddBindMessage(**self._bind_addrs[i])
            self.assertEqual(vars(msg_add_bind), vars(self._dumped_binds[i]))

        self.reopen_handle()

        self._dumped_binds = []
        self.get_bind()
        self.assertEqual(len(self._dumped_binds), 0)

if __name__ == "__main__":
    testutil.main()

