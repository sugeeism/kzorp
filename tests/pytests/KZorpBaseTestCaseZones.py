from KZorpComm import KZorpComm
import testutil
import kzorp.netlink as netlink
import kzorp.kzorp_netlink as kzorp_netlink
import socket


class KZorpBaseTestCaseZones(KZorpComm):
    _dumped_zones = []

    def _dump_zone_handler(self, message):
        self._dumped_zones.append(message)

    def check_zone_num(self, num_zones = 0, in_transaction = True):
        self._dumped_zones = []

        if in_transaction == True:
            self.start_transaction()

        self.send_message(kzorp_netlink.KZorpGetZoneMessage(None), message_handler = self._dump_zone_handler, dump = True)

        if in_transaction == True:
            self.end_transaction()

        self.assertEqual(num_zones, len(self._dumped_zones))

    def get_zone_attrs(self, message):
        self.assertEqual(message.command, kzorp_netlink.KZNL_MSG_ADD_ZONE)

        attrs = message.get_attributes()

        return attrs

    def get_zone_name(self, message):
        attrs = self.get_zone_attrs(message)
        if attrs.has_key(kzorp_netlink.KZNL_ATTR_ZONE_NAME) == True:
            return kzorp_netlink.parse_name_attr(attrs[kzorp_netlink.KZNL_ATTR_ZONE_NAME])

        return None

    def get_zone_uname(self, message):
        attrs = self.get_zone_attrs(message)
        self.assertEqual(attrs.has_key(kzorp_netlink.KZNL_ATTR_ZONE_UNAME), True)

        return kzorp_netlink.parse_name_attr(attrs[kzorp_netlink.KZNL_ATTR_ZONE_UNAME])

    def get_zone_range(self, message):
        attrs = self.get_zone_attrs(message)
        self.assertEqual(attrs.has_key(kzorp_netlink.KZNL_ATTR_ZONE_RANGE), True)

        (family, addr, mask) = kzorp_netlink.parse_inet_range_attr(attrs[kzorp_netlink.KZNL_ATTR_ZONE_RANGE])

        return "%s/%s" % (socket.inet_ntop(family, addr), socket.inet_ntop(family, mask))

    def _check_zone_params(self, add_zone_message, zone_data):
        self.assertEqual(self.get_zone_name(add_zone_message), zone_data['name'])
        self.assertEqual(self.get_zone_uname(add_zone_message), zone_data['uname'])

        family = zone_data['family']
        self.assertEqual(self.get_zone_range(add_zone_message), "%s/%s" % (zone_data['address'], testutil.size_to_mask(family, zone_data['mask'])))

if __name__ == "__main__":
    testutil.main()
