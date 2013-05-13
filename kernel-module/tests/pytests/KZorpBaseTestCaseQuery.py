from KZorpBaseTestCaseDispatchers import KZorpBaseTestCaseDispatchers
from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
import testutil
import os

class KZorpBaseTestCaseQuery(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):

    _object_count = 0

    def __init__(self, *args):
        KZorpBaseTestCaseDispatchers.__init__(self, *args)
        KZorpBaseTestCaseZones.__init__(self, *args)

        self._initialized = False

        self._dumped_diszpancsers = []

        if (KZorpBaseTestCaseQuery._object_count == 0):
            self.initialize()
        KZorpBaseTestCaseQuery._object_count += 1

    def __del__(self):
        KZorpBaseTestCaseQuery._object_count -= 1
        if (KZorpBaseTestCaseQuery._object_count == 0):
            self.deinitialize()

    def initialize(self):
        os.system('modprobe dummy numdummies=6')
        os.system('ifconfig dummy0 10.99.201.1 netmask 255.255.255.0')
        os.system('ifconfig dummy1 10.99.202.2 netmask 255.255.255.0')
        os.system('ifconfig dummy2 10.99.203.3 netmask 255.255.255.0')
        os.system('ifconfig dummy3 10.99.204.4 netmask 255.255.255.0')
        os.system('ifconfig dummy4 10.99.205.5 netmask 255.255.255.0')
        os.system('ifconfig dummy5 10.99.205.6 netmask 255.255.255.0')
        os.system('echo 0x1 > /sys/class/net/dummy3/netdev_group')
        os.system('echo 0x1 > /sys/class/net/dummy4/netdev_group')
        os.system('echo 0x2 > /sys/class/net/dummy0/netdev_group')

    def deinitialize(self):
        os.system('rmmod dummy')

    def get_dispatcher_attrs(self, message):
        attrs = message.get_attributes()
        return attrs

    def get_service_name(self, message):
        return message.service

    def get_client_zone_name(self, message):
        attrs = message.get_attributes()
        client_zone = "not found"
        if attrs.has_key(KZNL_ATTR_QUERY_CLIENT_ZONE):
            client_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_CLIENT_ZONE])
        return client_zone
    def get_server_zone_name(self, message):
        attrs = message.get_attributes()
        server_zone = "not found"
        if attrs.has_key(KZNL_ATTR_QUERY_SERVER_ZONE):
            server_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_SERVER_ZONE])
        return server_zone

    def _query_message_handler(self, msg):
        self._dumped_diszpancsers.append(msg)

if __name__ == "__main__":
    testutil.main()
