from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
import testutil
import errno
import kzorp.kzorp_netlink as kznl

class KZorpTestCaseTransaction(KZorpBaseTestCaseZones):
    def tearDown(self):
        self.flush_all()

    def test_transactions(self):
        # Start a transaction
        self.start_transaction(kznl.KZ_INSTANCE_GLOBAL, 123456789L)

        # Start the transaction again without end transaction
        message = kznl.KZorpStartTransactionMessage(kznl.KZ_INSTANCE_GLOBAL, 987654321L)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        # Commit the transaction without any change
        self.end_transaction()

        # Commit the transaction again out of the transaction
        res = self.send_message(kznl.KZorpCommitTransactionMessage(), False)
        self.assertEqual(res, -errno.ENOENT)

    def test_transaction_collision(self):
        self.start_transaction()

        message = kznl.KZorpStartTransactionMessage(kznl.KZ_INSTANCE_GLOBAL)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        self.end_transaction()

    def test_transaction_abort(self):
        self.start_transaction()
        self.send_message(kznl.KZorpAddZoneMessage('zone'))
        self.end_transaction()
        self.check_zone_num(1)

        # Start a transaction
        self.start_transaction()

        self.send_message(kznl.KZorpAddZoneMessage('a'))
        self.check_zone_num(1, False)

        # Abort the transaction
        self.reopen_handle()

        self.check_zone_num(1, False)

if __name__ == "__main__":
    testutil.main()
