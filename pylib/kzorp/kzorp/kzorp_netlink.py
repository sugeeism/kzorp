
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
import struct
import socket
from netlink import *
import pprint

def enum(*args, **kw):

    def reverse_enumerate(s):
        return zip(s, range(len(s)))

    def to_string_method(enums):
        rev_map=dict((v,k) for k, v in enums.iteritems())
        return staticmethod(lambda value: rev_map[value])

    enums = dict(reverse_enumerate(args), **kw)
    return type('Enum', (object,), dict(enums, to_string=to_string_method(enums)))

# message types
KZNL_MSG_INVALID             = 0
KZNL_MSG_GET_VERSION         = 1
KZNL_MSG_START               = 2
KZNL_MSG_COMMIT              = 3
KZNL_MSG_FLUSH_ZONE          = 4
KZNL_MSG_ADD_ZONE            = 5
KZNL_MSG_GET_ZONE            = 6
KZNL_MSG_FLUSH_SERVICE       = 7
KZNL_MSG_ADD_SERVICE         = 8
KZNL_MSG_ADD_SERVICE_NAT_SRC = 9
KZNL_MSG_ADD_SERVICE_NAT_DST = 10
KZNL_MSG_GET_SERVICE         = 11
KZNL_MSG_FLUSH_DISPATCHER    = 12
KZNL_MSG_ADD_DISPATCHER      = 13
KZNL_MSG_GET_DISPATCHER      = 14
KZNL_MSG_QUERY               = 15
KZNL_MSG_ADD_RULE            = 16
KZNL_MSG_ADD_RULE_ENTRY      = 17
KZNL_MSG_ADD_BIND            = 18
KZNL_MSG_GET_BIND            = 19
KZNL_MSG_FLUSH_BIND          = 20
KZNL_MSG_QUERY_REPLY         = 21
KZNL_MSG_MAX                 = 22

# attribute types
KZNL_ATTR_INVALID                       = 0
KZNL_ATTR_INSTANCE_NAME                 = 1
KZNL_ATTR_ZONE_NAME                     = 2
KZNL_ATTR_ZONE_UNAME                    = 3
KZNL_ATTR_ZONE_PNAME                    = 4
KZNL_ATTR_ZONE_RANGE                    = 5
KZNL_ATTR_SVC_PARAMS                    = 6
KZNL_ATTR_SVC_NAME                      = 7
KZNL_ATTR_SVC_ROUTER_DST_ADDR           = 8
KZNL_ATTR_SVC_NAT_SRC                   = 9
KZNL_ATTR_SVC_NAT_DST                   = 10
KZNL_ATTR_SVC_NAT_MAP                   = 11
KZNL_ATTR_SVC_SESSION_COUNT             = 12
KZNL_ATTR_DPT_NAME                      = 13
KZNL_ATTR_QUERY_PARAMS                  = 14
KZNL_ATTR_QUERY_CLIENT_ZONE             = 15
KZNL_ATTR_QUERY_SERVER_ZONE             = 16
KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS = 17
KZNL_ATTR_N_DIMENSION_RULE_ID           = 18
KZNL_ATTR_N_DIMENSION_RULE_SERVICE      = 19
KZNL_ATTR_N_DIMENSION_IFACE             = 20
KZNL_ATTR_N_DIMENSION_PROTO             = 21
KZNL_ATTR_N_DIMENSION_SRC_PORT          = 22
KZNL_ATTR_N_DIMENSION_DST_PORT          = 23
KZNL_ATTR_N_DIMENSION_SRC_IP            = 24
KZNL_ATTR_N_DIMENSION_SRC_ZONE          = 25
KZNL_ATTR_N_DIMENSION_DST_IP            = 26
KZNL_ATTR_N_DIMENSION_DST_ZONE          = 27
KZNL_ATTR_N_DIMENSION_IFGROUP           = 28
KZNL_ATTR_CONFIG_COOKIE                 = 29
KZNL_ATTR_INET4_ADDR                    = 30
KZNL_ATTR_INET4_SUBNET                  = 31
KZNL_ATTR_INET6_ADDR                    = 32
KZNL_ATTR_INET6_SUBNET                  = 33
KZNL_ATTR_N_DIMENSION_SRC_IP6           = 34
KZNL_ATTR_N_DIMENSION_DST_IP6           = 35
KZNL_ATTR_QUERY_PARAMS_SRC_IP           = 36
KZNL_ATTR_QUERY_PARAMS_DST_IP           = 37
KZNL_ATTR_SVC_ROUTER_DST_PORT           = 38
KZNL_ATTR_BIND_ADDR                     = 39
KZNL_ATTR_BIND_PORT                     = 40
KZNL_ATTR_BIND_PROTO                    = 41
KZNL_ATTR_MAJOR_VERSION                 = 42
KZNL_ATTR_COMPAT_VERSION                = 43
KZNL_ATTR_SVC_INET4_DENY_SETTING        = 44
KZNL_ATTR_SVC_INET6_DENY_SETTING        = 45
KZNL_ATTR_N_DIMENSION_DST_IFACE         = 46
KZNL_ATTR_N_DIMENSION_DST_IFGROUP       = 47
KZNL_ATTR_N_DIMENSION_REQID             = 48
KZNL_ATTR_QUERY_PARAMS_REQID            = 49
KZNL_ATTR_MAX                           = 50

# list of attributes in an N dimension rule
N_DIMENSION_ATTRS = [
  KZNL_ATTR_N_DIMENSION_IFACE,
  KZNL_ATTR_N_DIMENSION_PROTO,
  KZNL_ATTR_N_DIMENSION_SRC_PORT,
  KZNL_ATTR_N_DIMENSION_DST_PORT,
  KZNL_ATTR_N_DIMENSION_SRC_IP,
  KZNL_ATTR_N_DIMENSION_SRC_ZONE,
  KZNL_ATTR_N_DIMENSION_DST_IP,
  KZNL_ATTR_N_DIMENSION_DST_ZONE,
  KZNL_ATTR_N_DIMENSION_IFGROUP,
  KZNL_ATTR_N_DIMENSION_SRC_IP6,
  KZNL_ATTR_N_DIMENSION_DST_IP6,
  KZNL_ATTR_N_DIMENSION_DST_IFACE,
  KZNL_ATTR_N_DIMENSION_DST_IFGROUP,
  KZNL_ATTR_N_DIMENSION_REQID,
]

# name of global instance
KZ_INSTANCE_GLOBAL = ".global"

# transaction types
KZ_TR_TYPE_INVALID = 0
KZ_TR_TYPE_ZONE = 1
KZ_TR_TYPE_SERVICE = 2
KZ_TR_TYPE_DISPATCHER = 3

# service types
KZ_SVC_INVALID = 0
KZ_SVC_PROXY = 1
KZ_SVC_FORWARD = 2
KZ_SVC_DENY = 3

# service flags
KZF_SVC_TRANSPARENT = 1
KZF_SVC_FORGE_ADDR = 2
KZF_SVC_LOGGING = 4

DenyIPv4 = enum(DROP=0,
                TCP_RESET=1,
                ICMP_NET_UNREACHABLE=2,
                ICMP_HOST_UNREACHABLE=3,
                ICMP_PROTO_UNREACHABLE=4,
                ICMP_PORT_UNREACHABLE=5,
                ICMP_NET_PROHIBITED=6,
                ICMP_HOST_PROHIBITED=7,
                ICMP_ADMIN_PROHIBITED=8)

DenyIPv6 = enum(DROP=0,
                TCP_RESET=1,
                ICMP_NO_ROUTE=2,
                ICMP_ADMIN_PROHIBITED=3,
                ICMP_ADDR_UNREACHABLE=4,
                ICMP_PORT_UNREACHABLE=5)

# service NAT entry flags
KZ_SVC_NAT_MAP_IPS = 1
KZ_SVC_NAT_MAP_PROTO_SPECIFIC = 2

# dispatcher bind address port ranges
KZF_DPT_PORT_RANGE_SIZE = 8

def mask_to_description(mask, definition):
    text = ""
    first = True
    for i in definition.keys():
        if (mask & i):
            if first:
                text = definition[i]
                first = False
            else:
                text = text + ",%s" % (definition[i])
    return text

def get_family_from_attr(attr):
    if attr.type == KZNL_ATTR_INET4_ADDR or attr.type == KZNL_ATTR_INET4_SUBNET or \
       attr.type == KZNL_ATTR_N_DIMENSION_SRC_IP or attr.type == KZNL_ATTR_N_DIMENSION_DST_IP:
        family = socket.AF_INET
    elif attr.type == KZNL_ATTR_INET6_ADDR or attr.type == KZNL_ATTR_INET6_SUBNET or \
         attr.type == KZNL_ATTR_N_DIMENSION_SRC_IP6 or attr.type == KZNL_ATTR_N_DIMENSION_DST_IP6:
        family = socket.AF_INET6
    else:
        raise ValueError, "attribute not supported; type='%d'" % attr.type

    return family

###########################################################################
# helper functions to create/parse kzorp attributes
###########################################################################
def create_name_attr(type, name):
    data = "".join((struct.pack('>H', len(name)), name))
    return NetlinkAttribute(type, data=data)

def parse_name_attr(attr):
    (len,) = struct.unpack('>H', attr.get_data()[:2])
    (name,) = struct.unpack(str(len) + 's', attr.get_data()[2 : 2 + len])
    return name

def create_inet_subnet_attr(attr_type, family, address, mask):
    """Create an netlink attribute which stores an IP subnet.

    Keyword arguments:
    addr -- an IP address in binary format (returned by inet_pton)
    mask -- an IP netmask in binary format (returned by inet_pton)

    """
    if family != socket.AF_INET and family != socket.AF_INET6:
        raise NetlinkException, "protocol family not supported"

    if (family == socket.AF_INET):
        data = struct.pack('4s',  address) + struct.pack('4s',  mask)
    else:
        data = struct.pack('16s',  address) + struct.pack('16s',  mask)

    return NetlinkAttribute(attr_type, data = data)

def parse_inet_subnet_attr(attr, family):
    """Parse an netlink attribute which stores an IP subnet.

    Return list of protocol family, address and netmask

    """
    if family != socket.AF_INET and family != socket.AF_INET6:
        raise NetlinkException, "protocol family not supported"

    if family == socket.AF_INET:
        data = struct.unpack('4s', attr.read_data(4)) + struct.unpack('4s', attr.read_data(4))
    else:
        data = struct.unpack('16s', attr.read_data(16)) + struct.unpack('16s', attr.read_data(16))

    return data

def create_inet_range_attr(type, family, address, mask):
    if family == socket.AF_INET:
        attr = create_inet_subnet_attr(KZNL_ATTR_INET4_SUBNET, family, address, mask)
        return NetlinkAttribute(type, attrs = [attr])
    elif family == socket.AF_INET6:
        attr = create_inet_subnet_attr(KZNL_ATTR_INET6_SUBNET, family, address, mask)
        return NetlinkAttribute(type, attrs = [attr])
    else:
        raise ValueError, "address family not supported; family='%d'" % family

def parse_inet_range_attr(attr):
    attrs = attr.get_attributes()
    if len(attrs) == 0:
        raise ValueError, "zone range attribute does not contain a nested attribute"
    elif len(attrs) > 1:
        raise ValueError, "zone range attribute contains more than one nested attribute"

    attr = attrs[0]
    family = get_family_from_attr(attr)
    (addr, mask) = parse_inet_subnet_attr(attr, family)
    return (family, addr, mask)

def _create_inet_addr_attr(type, family, address):
    """Create an netlink attribute which stores an IP address.

    Keyword arguments:
    addr -- an IP address in binary format (returned by inet_pton)

    """
    if family != socket.AF_INET and family != socket.AF_INET6:
        raise NetlinkException, "protocol family not supported"

    if (family == socket.AF_INET):
        data = struct.pack('4s',  address)
    else:
        data = struct.pack('16s',  address)

    return NetlinkAttribute(type, data = data)

def _parse_inet_addr_attr(attr, family):
    """Parse an netlink attribute which stores an IP address.

    Return list of protocol family and address

    """
    if (family != socket.AF_INET and family != socket.AF_INET6):
        raise NetlinkException, "protocol family not supported"

    if family == socket.AF_INET:
        data = struct.unpack('4s', attr.read_data(4))
    else:
        data = struct.unpack('16s', attr.read_data(16))

    return data[0]

def create_inet_addr_attr(type, family, address):
    if family == socket.AF_INET:
        attr = _create_inet_addr_attr(KZNL_ATTR_INET4_ADDR, family, address)
        return NetlinkAttribute(type, attrs = [attr])
    elif family == socket.AF_INET6:
        attr = _create_inet_addr_attr(KZNL_ATTR_INET6_ADDR, family, address)
        return NetlinkAttribute(type, attrs = [attr])
    else:
        raise ValueError, "address family not supported; family='%d'" % family

def parse_inet_addr_attr(attr):
    attrs = attr.get_attributes()
    if len(attrs) == 0:
        raise ValueError, "inet addr attribute does not contain a nested attribute"
    elif len(attrs) > 1:
        raise ValueError, "inet addr attribute contains more than one nested attribute"

    attr = attrs[0]
    family = get_family_from_attr(attr)
    address = _parse_inet_addr_attr(attr, family)
    return (family, address)

def create_port_range_attr(type, range_from, range_to):
    return NetlinkAttribute(type, data = struct.pack('>HH', range_from, range_to))

def parse_port_range_attr(attr):
    return struct.unpack('>HH', attr.get_data()[:4])

def create_nat_range_attr(type, flags, min_ip, max_ip, min_port, max_port):
    data = struct.pack('>IIIHH', flags, min_ip, max_ip, min_port, max_port)
    return NetlinkAttribute(type, data = data)

def parse_nat_range_attr(attr):
    return struct.unpack('>IIIHH', attr.get_data()[:16])

def create_address_attr(type, proto, ip, port):
    return NetlinkAttribute(type, data = struct.pack('>IHB', ip, port, proto))

def parse_address_attr(attr):
    return struct.unpack('>IHB', attr.get_data()[:7])

def create_bind_addr_attr(type, proto, ip, ports):
    if len(ports) > KZF_DPT_PORT_RANGE_SIZE:
        raise ValueError, "bind address contains too many port ranges, %s allowed" % KZF_DPT_PORT_RANGE_SIZE
    data = struct.pack('>I', ip)
    for r in ports:
        data = "".join((data, struct.pack('>HH', r[0], r[1])))
    if len(ports) < KZF_DPT_PORT_RANGE_SIZE:
        data = "".join((data, "\0" * 4 * (KZF_DPT_PORT_RANGE_SIZE - len(ports))))
    data = "".join((data, struct.pack('BB', len(ports), proto)))
    return NetlinkAttribute(type, data = data)

def parse_bind_addr_attr(attr):
    (addr,) = struct.unpack('>I', attr.get_data()[:4])
    (num_ports, proto) = struct.unpack('BB', attr.get_data()[36:38])
    ports = []
    for i in range(num_ports):
        (start, end) = struct.unpack('>HH', attr.get_data()[4 + 4 * i : 8 + 4 * i])
        ports.append((start, end))
    return (proto, addr, ports)

def parse_n_dimension_attr(attr):
    (num_rules, ) = struct.unpack('>I', attr.get_data()[:4])
    return num_rules

def parse_rule_attrs(attr):
    (rule_id, ) = struct.unpack('>I', attr[KZNL_ATTR_N_DIMENSION_RULE_ID].get_data()[:4])
    service = parse_name_attr(attr[KZNL_ATTR_N_DIMENSION_RULE_SERVICE])
    dpt_name = parse_name_attr(attr[KZNL_ATTR_DPT_NAME])
    rule_entry_nums = {}

    for dim_type in N_DIMENSION_ATTRS:
        if attr and attr.has_key(dim_type):
            data = attr[dim_type].get_data()
            value = struct.unpack('>I', data[:4])[0]
            rule_entry_nums[dim_type] = value

    return (dpt_name, rule_id, service, rule_entry_nums)

def parse_rule_entry_attrs(attr):
    if attr.has_key(KZNL_ATTR_DPT_NAME):
        dpt_name = parse_name_attr(attr[KZNL_ATTR_DPT_NAME])
    else:
        raise AttributeRequiredError, "KZNL_ATTR_DPT_NAME"

    (rule_id, ) = struct.unpack('>I', attr[KZNL_ATTR_N_DIMENSION_RULE_ID].get_data()[:4])
    rule_entries = {}

    for dim_type in N_DIMENSION_ATTRS:
        if attr and attr.has_key(dim_type):
            data = attr[dim_type].get_data()

            if dim_type == KZNL_ATTR_N_DIMENSION_PROTO:
                value = struct.unpack('>B', data[:1])[0]
            elif dim_type == KZNL_ATTR_N_DIMENSION_DST_PORT or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_PORT:
                value = parse_port_range_attr(attr[dim_type])
            elif dim_type == KZNL_ATTR_N_DIMENSION_DST_IP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_IP6 or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP6:
                value = parse_inet_subnet_attr(attr[dim_type], get_family_from_attr(attr[dim_type]))
            elif dim_type == KZNL_ATTR_N_DIMENSION_IFGROUP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_IFGROUP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_REQID:
                value = struct.unpack('>I',  data[:4])[0]
            elif dim_type == KZNL_ATTR_N_DIMENSION_IFACE    or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_ZONE or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_ZONE or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_IFACE:
                value = parse_name_attr(attr[dim_type])
            else:
                raise ValueError, "dispatcher dimension type is invalid; type='%d'" % dim_type

            rule_entries[dim_type] = value

    return (dpt_name, rule_id, rule_entries)

def create_service_params_attr(type, svc_type, svc_flags):
    return NetlinkAttribute(type, data = struct.pack('>IB', svc_flags, svc_type))

def parse_service_params_attr(attr):
    return struct.unpack('>IB', attr.get_data()[:5])

def create_query_params_attr(type, proto, sport, dport, iface):
    data = struct.pack('>HH', sport, dport)
    data = "".join((data, iface, "\0" * (16 - len(iface)), struct.pack('>B', proto)))
    return NetlinkAttribute(type, data = data)

def create_deny_setting_attr(type, setting):
    return NetlinkAttribute.create_int8(type, setting)

def parse_deny_setting_attr(attr):
    return attr.parse_int8()


# transactions
class KZorpStartTransactionMessage(GenericNetlinkMessage):
    command = KZNL_MSG_START

    def __init__(self, instance_name, config_cookie=0):
        super(KZorpStartTransactionMessage, self).__init__(self.command, version = 1)

        self.instance_name = instance_name
        self.config_cookie = config_cookie

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_INSTANCE_NAME, self.instance_name))
        if (self.config_cookie > 0):
            self.append_attribute(NetlinkAttribute.create_be64(KZNL_ATTR_CONFIG_COOKIE, self.config_cookie))

class KZorpCommitTransactionMessage(GenericNetlinkMessage):
    command = KZNL_MSG_COMMIT

    def __init__(self):
        super(KZorpCommitTransactionMessage, self).__init__(self.command, version = 1)

# flush
class KZorpFlushMessage(GenericNetlinkMessage):
    command = KZNL_MSG_INVALID

    def __init__(self):
        super(KZorpFlushMessage, self).__init__(self.command, version = 1)

class KZorpFlushZonesMessage(KZorpFlushMessage):
    command = KZNL_MSG_FLUSH_ZONE

class KZorpFlushServicesMessage(KZorpFlushMessage):
    command = KZNL_MSG_FLUSH_SERVICE

class KZorpFlushDispatchersMessage(KZorpFlushMessage):
    command = KZNL_MSG_FLUSH_DISPATCHER

class KZorpFlushBindsMessage(KZorpFlushMessage):
    command = KZNL_MSG_FLUSH_BIND

# service
class KZorpAddServiceMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_SERVICE

    service_flags = {1: "transparent", 2: "forge_addr", 4: "logging"}

    def __init__(self, name, service_type, flags, count, version=1):
        super(KZorpAddServiceMessage, self).__init__(self.command, version)

        self.name = name
        self.service_type = service_type
        self.flags = flags
        self.count = count

    def _build_payload(self):
        self.append_attribute(create_service_params_attr(KZNL_ATTR_SVC_PARAMS, self.service_type, self.flags))
        self.append_attribute(create_name_attr(KZNL_ATTR_SVC_NAME, self.name))
        self.append_attribute(NetlinkAttribute.create_be32(KZNL_ATTR_SVC_SESSION_COUNT, self.count))

    @staticmethod
    def get_kz_attr(attrs, key_type, parser):
        attribute = attrs.get(key_type)
        if attribute:
            return parser(attribute)
        else:
            return None

    @classmethod
    def parse(cls, version, data):

        # which service message class to instantiate based on service type
        service_types = {
            KZ_SVC_PROXY   : KZorpAddProxyServiceMessage,
            KZ_SVC_FORWARD : KZorpAddForwardServiceMessage,
            KZ_SVC_DENY    : KZorpAddDenyServiceMessage
        }

        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)
        flags, service_type = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_PARAMS, parse_service_params_attr)
        if service_type in service_types:
            return service_types[service_type].parse(version, data)
        else:
            raise AttributeRequiredError, "KZNL_ATTR_SVC_PARAMS"

    @classmethod
    def parse_base_attrs(cls, version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        name = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_NAME, parse_name_attr)
        flags, service_type = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_PARAMS, parse_service_params_attr)
        count = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_SESSION_COUNT, NetlinkAttribute.parse_be32)

        return (name, service_type, flags, count)

    def __str__(self):
        flags_str = mask_to_description(self.flags, self.service_flags)

        return "Service name='%s', flags='%s', type='%s', session_count='%d'" % \
               (self.name, flags_str, self.type_string, self.count)


class KZorpAddProxyServiceMessage(KZorpAddServiceMessage):

    type_string = "Service"

    def __init__(self, name, flags=KZF_SVC_LOGGING, count=0):
        super(KZorpAddProxyServiceMessage, self).__init__(name, KZ_SVC_PROXY, flags, count)

        self._build_payload()

    @classmethod
    def parse(cls, version, data):
        name, _service_type, flags, count = super(KZorpAddProxyServiceMessage, cls).parse_base_attrs(version, data)

        return cls(name, flags, count)


class KZorpAddForwardServiceMessage(KZorpAddServiceMessage):

    type_string = "PFService"

    def __init__(self, name, flags=0, count=0, dst_family=None, dst_ip=None, dst_port=None):
        super(KZorpAddForwardServiceMessage, self).__init__(name, KZ_SVC_FORWARD, flags, count)
        self.dst_family = dst_family
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self._build_payload()

    def _build_payload(self):
        super(KZorpAddForwardServiceMessage, self)._build_payload()
        if self.dst_family and self.dst_ip and self.dst_port:
            self.append_attribute(create_inet_addr_attr(KZNL_ATTR_SVC_ROUTER_DST_ADDR, self.dst_family, self.dst_ip))
            self.append_attribute(NetlinkAttributePort(KZNL_ATTR_SVC_ROUTER_DST_PORT, self.dst_port))

    @classmethod
    def parse(cls, version, data):
        name, _service_type, flags, count = super(KZorpAddForwardServiceMessage, cls).parse_base_attrs(version, data)

        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        if attrs.has_key(KZNL_ATTR_SVC_ROUTER_DST_ADDR) and attrs.has_key(KZNL_ATTR_SVC_ROUTER_DST_PORT):
            dst_family, dst_ip = parse_inet_addr_attr(attrs[KZNL_ATTR_SVC_ROUTER_DST_ADDR])
            dst_port = parse_port_attr(attrs[KZNL_ATTR_SVC_ROUTER_DST_PORT])
        else:
            dst_family, dst_ip, dst_port = None, None, None

        return cls(name, flags, count, dst_family, dst_ip, dst_port)

    def __str__(self):
        parent = super(KZorpAddForwardServiceMessage, self).__str__()
        if self.dst_ip and self.dst_port:
            return "\n".join((parent, "        router_dst='%s:%d'" % (socket.inet_ntop(self.dst_family, self.dst_ip), self.dst_port)))
        else:
            return parent


class KZorpAddDenyServiceMessage(KZorpAddServiceMessage):

    type_string = "DenyService"

    deny_ipv4_types = {
        DenyIPv4.DROP: 'Drop',
        DenyIPv4.TCP_RESET: 'TCP reset',
        DenyIPv4.ICMP_NET_UNREACHABLE: 'Network unreachable',
        DenyIPv4.ICMP_HOST_UNREACHABLE: 'Host unreachable',
        DenyIPv4.ICMP_PROTO_UNREACHABLE: 'Proto unreachable',
        DenyIPv4.ICMP_PORT_UNREACHABLE: 'Port unreachable',
        DenyIPv4.ICMP_NET_PROHIBITED: 'Network prohibited',
        DenyIPv4.ICMP_HOST_PROHIBITED: 'Host prohibited',
        DenyIPv4.ICMP_ADMIN_PROHIBITED: 'Administratively prohibited',
        }

    deny_ipv6_types = {
        DenyIPv6.DROP: 'Drop',
        DenyIPv6.TCP_RESET: 'TCP reset',
        DenyIPv6.ICMP_NO_ROUTE: 'No route',
        DenyIPv6.ICMP_ADMIN_PROHIBITED: 'Administratively prohibited',
        DenyIPv6.ICMP_ADDR_UNREACHABLE: 'Address unreachable',
        DenyIPv6.ICMP_PORT_UNREACHABLE: 'Port unreachable',
        }

    def __init__(self, name, logging, count, ipv4_settings, ipv6_settings):
        super(KZorpAddDenyServiceMessage, self).__init__(name, KZ_SVC_DENY, KZF_SVC_LOGGING if logging else 0, count)
        self.logging = logging
        self.ipv4_settings = ipv4_settings
        self.ipv6_settings = ipv6_settings

        self._build_payload()

    def _build_payload(self):
        super(KZorpAddDenyServiceMessage, self)._build_payload()
        self.append_attribute(create_deny_setting_attr(KZNL_ATTR_SVC_INET4_DENY_SETTING, self.ipv4_settings))
        self.append_attribute(create_deny_setting_attr(KZNL_ATTR_SVC_INET6_DENY_SETTING, self.ipv6_settings))

    @classmethod
    def parse(cls, version, data):
        name, _service_type, flags, count = super(KZorpAddDenyServiceMessage, cls).parse_base_attrs(version, data)
        logging = flags & KZF_SVC_LOGGING > 0

        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        ipv4_setting = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_INET4_DENY_SETTING, parse_deny_setting_attr)
        ipv6_setting = cls.get_kz_attr(attrs, KZNL_ATTR_SVC_INET6_DENY_SETTING, parse_deny_setting_attr)

        return cls(name, logging, count, ipv4_setting, ipv6_setting)

    def __str__(self):
        parent = super(KZorpAddDenyServiceMessage, self).__str__()
        deny_ipv4_line = "        deny_ipv4='%s'" % self.deny_ipv4_types[self.ipv4_settings]
        deny_ipv6_line = "        deny_ipv6='%s'" % self.deny_ipv6_types[self.ipv6_settings]

        return "\n".join((parent, deny_ipv4_line, deny_ipv6_line))


class KZorpGetServiceMessage(GenericNetlinkMessage):
    command = KZNL_MSG_GET_SERVICE

    def __init__(self, name=None):
        super(KZorpGetServiceMessage, self).__init__(self.command, version = 1)

        self.name = name

        self._build_payload()

    def _build_payload(self):
        if self.name:
            self.append_attribute(create_name_attr(KZNL_ATTR_SVC_NAME, self.name))

class KZorpAddServiceNATMappingMessage(GenericNetlinkMessage):

    def __init__(self, name, nat_src, nat_map, nat_dst=None):
        super(KZorpAddServiceNATMappingMessage, self).__init__(self.command, version = 1)

        self.name = name
        self.nat_src = nat_src
        self.nat_dst = nat_dst
        self.nat_map = nat_map

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_SVC_NAME, self.name))

        (flags, min_ip, max_ip, min_port, max_port) = self.nat_src
        self.append_attribute(create_nat_range_attr(KZNL_ATTR_SVC_NAT_SRC, flags, min_ip, max_ip, min_port, max_port))

        (flags, min_ip, max_ip, min_port, max_port) = self.nat_map
        self.append_attribute(create_nat_range_attr(KZNL_ATTR_SVC_NAT_MAP, flags, min_ip, max_ip, min_port, max_port))

        if self.nat_dst:
            (flags, min_ip, max_ip, min_port, max_port) = self.nat_dst
            self.append_attribute(create_nat_range_attr(KZNL_ATTR_SVC_NAT_DST, flags, min_ip, max_ip, min_port, max_port))

    @classmethod
    def parse(cls, version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)
        if attrs.has_key(KZNL_ATTR_SVC_NAME):
            name = parse_name_attr(attrs[KZNL_ATTR_SVC_NAME])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_SVC_NAME"

        if attrs.has_key(KZNL_ATTR_SVC_NAT_SRC):
            nat_src = parse_nat_range_attr(attrs[KZNL_ATTR_SVC_NAT_SRC])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_SVC_NAT_SRC"

        if attrs.has_key(KZNL_ATTR_SVC_NAT_DST):
            nat_dst = parse_nat_range_attr(attrs[KZNL_ATTR_SVC_NAT_DST])
        else:
            nat_dst = None

        if attrs.has_key(KZNL_ATTR_SVC_NAT_MAP):
            nat_map = parse_nat_range_attr(attrs[KZNL_ATTR_SVC_NAT_MAP])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_SVC_NAT_MAP"

        return cls(name, nat_src, nat_map, nat_dst)

    def __str__(self):

        def nat_range_str(nat):

            def inet_ntoa(a):
                return "%s.%s.%s.%s" % ((a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff)

            flags, ip1, ip2, p1, p2 = nat
            if ip1 == ip2:
                return "%s" % (inet_ntoa(ip1),)
            else:
                return "(%s - %s)" % (inet_ntoa(ip1), inet_ntoa(ip2))

        if self.command == KZNL_MSG_ADD_SERVICE_NAT_SRC:
            msg = "        SNAT: "
        else:
            msg = "        DNAT: "

        if self.nat_dst:
            return "%s src %s dst %s mapped to %s" % \
                   (msg, nat_range_str(self.nat_src), \
                    nat_range_str(self.nat_dst), \
                    nat_range_str(self.nat_map))
        else:
            return "%s src %s mapped to %s" % \
                   (msg, nat_range_str(self.nat_src), \
                    nat_range_str(self.nat_map))

class KZorpAddServiceSourceNATMappingMessage(KZorpAddServiceNATMappingMessage):
    command = KZNL_MSG_ADD_SERVICE_NAT_SRC

class KZorpAddServiceDestinationNATMappingMessage(KZorpAddServiceNATMappingMessage):
    command = KZNL_MSG_ADD_SERVICE_NAT_DST

class KZorpGetServiceMessage(GenericNetlinkMessage):
    command = KZNL_MSG_GET_SERVICE

    def __init__(self, name = None):
        super(KZorpGetServiceMessage, self).__init__(self.command, version = 1)

        self.name = name

        self._build_payload()

    def _build_payload(self):
        if self.name:
            self.append_attribute(create_name_attr(KZNL_ATTR_SVC_NAME, self.name))

# zone
class KZorpAddZoneMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_ZONE

    def __init__(self, name, family=socket.AF_INET, address = None, mask = None, uname = None, pname = None):
        super(KZorpAddZoneMessage, self).__init__(self.command, version = 1)

        self.name = name
        self.uname = uname
        self.pname = pname
        self.family = family
        self.address = address
        self.mask = mask

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_ZONE_NAME, self.name))
        if self.uname != None:
            self.append_attribute(create_name_attr(KZNL_ATTR_ZONE_UNAME, self.uname))
        if self.pname != None:
            self.append_attribute(create_name_attr(KZNL_ATTR_ZONE_PNAME, self.pname))
        if self.address != None and self.mask != None:
            self.append_attribute(create_inet_range_attr(KZNL_ATTR_ZONE_RANGE, self.family, self.address, self.mask))

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)
        kw = {}

        if attrs.has_key(KZNL_ATTR_ZONE_NAME):
            name = parse_name_attr(attrs[KZNL_ATTR_ZONE_NAME])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_ZONE_NAME"

        if attrs.has_key(KZNL_ATTR_ZONE_UNAME):
            kw['uname'] = parse_name_attr(attrs[KZNL_ATTR_ZONE_UNAME])

        if attrs.has_key(KZNL_ATTR_ZONE_PNAME):
            kw['pname'] = parse_name_attr(attrs[KZNL_ATTR_ZONE_PNAME])

        if attrs.has_key(KZNL_ATTR_ZONE_RANGE):
            (family, address, mask) = parse_inet_range_attr(attrs[KZNL_ATTR_ZONE_RANGE])
            kw['family'] = family
            kw['address'] = address
            kw['mask'] = mask

        return KZorpAddZoneMessage(name, **kw)

    def __str__(self):
        res = "Zone unique_name='%s', visible_name='%s', admin_parent='%s'" % (self.uname, self.name, self.pname)
        if self.address:
            range_str = "range '%s/%s'" % (socket.inet_ntop(self.family, self.address), socket.inet_ntop(self.family, self.mask))
            res += ",\n        %s" % range_str
        return res

class KZorpGetZoneMessage(GenericNetlinkMessage):
    command = KZNL_MSG_GET_ZONE

    def __init__(self, name=None):
        super(KZorpGetZoneMessage, self).__init__(self.command, version = 1)

        self.name = name

        self._build_payload()

    def _build_payload(self):
        if self.name:
            self.append_attribute(create_name_attr(KZNL_ATTR_ZONE_UNAME, self.name))

# dispatcher
class KZorpAddDispatcherMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_DISPATCHER

    def __init__(self, name, num_rules):
        super(KZorpAddDispatcherMessage, self).__init__(self.command, version = 1)

        self.name = name
        self.num_rules = num_rules

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_DPT_NAME, self.name))
        self.append_attribute(NetlinkAttribute.create_be32(KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS, self.num_rules))

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        if attrs.has_key(KZNL_ATTR_DPT_NAME):
            name = parse_name_attr(attrs[KZNL_ATTR_DPT_NAME])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_DPT_NAME"

        if attrs.has_key(KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS):
            num_rules = parse_n_dimension_attr(attrs[KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS])
        else:
            raise AttributeRequiredError, "KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS"

        return KZorpAddDispatcherMessage(name, num_rules)

    def __str__(self):
        addr_str = "        num_rules='%d'" % (self.num_rules)
        return "Dispatcher name='%s'\n%s" % (self.name, addr_str)

class KZorpAddRuleMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_RULE

    def __init__(self, dpt_name, rule_id, service, entry_nums):
        super(KZorpAddRuleMessage, self).__init__(self.command, version = 1)

        self.dpt_name = dpt_name
        self.rule_id = rule_id
        self.service = service
        self.entry_nums = entry_nums

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_DPT_NAME, self.dpt_name))
        self.append_attribute(NetlinkAttribute.create_be32(KZNL_ATTR_N_DIMENSION_RULE_ID, self.rule_id))
        self.append_attribute(create_name_attr(KZNL_ATTR_N_DIMENSION_RULE_SERVICE, self.service))

        for dim_type in N_DIMENSION_ATTRS:
            if self.entry_nums and self.entry_nums.has_key(dim_type):
                dim_size = self.entry_nums[dim_type]
                self.append_attribute(NetlinkAttribute.create_be32(dim_type, dim_size))

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        dpt_name, rule_id, service, rule_entry_nums = parse_rule_attrs(attrs)
        return KZorpAddRuleMessage(dpt_name, rule_id, service, rule_entry_nums)

    def __str__(self):
        return "        rule_id='%d', service='%s'" % (self.rule_id, self.service)

class KZorpAddRuleEntryMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_RULE_ENTRY

    def __init__(self, dpt_name, rule_id, entry_values):
        super(KZorpAddRuleEntryMessage, self).__init__(self.command, version = 1)

        self.dpt_name = dpt_name
        self.rule_id = rule_id
        self.entry_values = entry_values

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_DPT_NAME, self.dpt_name))
        self.append_attribute(NetlinkAttribute.create_be32(KZNL_ATTR_N_DIMENSION_RULE_ID, self.rule_id))

        for dim_type, value in self.entry_values.items():
            if dim_type == KZNL_ATTR_N_DIMENSION_PROTO:
                self.append_attribute(NetlinkAttribute.create_int8(dim_type, value))
            elif dim_type == KZNL_ATTR_N_DIMENSION_DST_PORT or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_PORT:
                self.append_attribute(create_port_range_attr(dim_type, value[0], value[1]))
            elif dim_type == KZNL_ATTR_N_DIMENSION_DST_IP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP:
                self.append_attribute(create_inet_subnet_attr(dim_type, socket.AF_INET, value[0], value[1]))
            elif dim_type == KZNL_ATTR_N_DIMENSION_DST_IP6 or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP6:
                self.append_attribute(create_inet_subnet_attr(dim_type, socket.AF_INET6, value[0], value[1]))
            elif dim_type == KZNL_ATTR_N_DIMENSION_IFGROUP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_IFGROUP or \
                 dim_type == KZNL_ATTR_N_DIMENSION_REQID:
                self.append_attribute(NetlinkAttribute.create_be32(dim_type, value))
            elif dim_type == KZNL_ATTR_N_DIMENSION_IFACE    or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_ZONE or \
                 dim_type == KZNL_ATTR_N_DIMENSION_SRC_ZONE or \
                 dim_type == KZNL_ATTR_N_DIMENSION_DST_IFACE:
                self.append_attribute(create_name_attr(dim_type, value))
            else:
                raise ValueError, "dispatcher dimension type is invalid; type='%d'" % dim_type

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        dpt_name, rule_id, entry_values = parse_rule_entry_attrs(attrs)

        return KZorpAddRuleEntryMessage(dpt_name, rule_id, entry_values)

    def aggregate_rule_entries(self, rule_entries):
        dpt_protocols = {6: "TCP", 17: "UDP"}

        for dim_type, value in self.entry_values.items():
            if not dim_type in rule_entries:
                rule_entries[dim_type] = []
            if dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP or dim_type == KZNL_ATTR_N_DIMENSION_DST_IP or \
               dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP6 or dim_type == KZNL_ATTR_N_DIMENSION_DST_IP6:
                family = socket.AF_INET if dim_type == KZNL_ATTR_N_DIMENSION_SRC_IP or dim_type == KZNL_ATTR_N_DIMENSION_DST_IP else socket.AF_INET6
                (addr, mask) = value
                rule_entries[dim_type].append((socket.inet_ntop(family, addr), socket.inet_ntop(family, mask)))
            elif dim_type == KZNL_ATTR_N_DIMENSION_PROTO:
                rule_entries[dim_type].append(dpt_protocols.get(value, str(value)))
            elif dim_type == KZNL_ATTR_N_DIMENSION_SRC_PORT or dim_type == KZNL_ATTR_N_DIMENSION_DST_PORT:
                rule_entries[dim_type].append((value[0], value[1]))
            else:
                rule_entries[dim_type].append(value)

class KZorpGetDispatcherMessage(GenericNetlinkMessage):
    command = KZNL_MSG_GET_DISPATCHER

    def __init__(self, name=None):
        super(KZorpGetDispatcherMessage, self).__init__(self.command, version = 1)

        self.name = name

        self._build_payload()

    def _build_payload(self):
        if self.name:
            self.append_attribute(create_name_attr(KZNL_ATTR_DPT_NAME, self.name))

# query
class KZorpQueryMessage(GenericNetlinkMessage):
    command = KZNL_MSG_QUERY

    def __init__(self, proto, family, saddr, sport, daddr, dport, iface, reqid = None):
        super(KZorpQueryMessage, self).__init__(self.command, version = 1)

        self.proto = proto
        self.family = family
        self.saddr = saddr
        self.sport = sport
        self.daddr = daddr
        self.dport = dport
        self.iface = iface
        self.reqid = reqid

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_inet_addr_attr(KZNL_ATTR_QUERY_PARAMS_SRC_IP, self.family, self.saddr))
        self.append_attribute(create_inet_addr_attr(KZNL_ATTR_QUERY_PARAMS_DST_IP, self.family, self.daddr))
        if self.reqid:
            self.append_attribute(NetlinkAttribute.create_be32(KZNL_ATTR_QUERY_PARAMS_REQID, self.reqid))
        self.append_attribute(create_query_params_attr(KZNL_ATTR_QUERY_PARAMS, self.proto, self.sport, self.dport, self.iface))

class KZorpQueryReplyMessage(GenericNetlinkMessage):
    command = KZNL_MSG_QUERY_REPLY

    def __init__(self, client_zone=None, server_zone=None, service=None, dispatcher=None):
        super(KZorpQueryReplyMessage, self).__init__(self.command, version = 1)

        self.client_zone = client_zone
        self.server_zone = server_zone
        self.service = service
        self.dispatcher = dispatcher

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        if attrs.has_key(KZNL_ATTR_QUERY_CLIENT_ZONE):
            client_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_CLIENT_ZONE])
        else:
            client_zone = None
        if attrs.has_key(KZNL_ATTR_QUERY_SERVER_ZONE):
            server_zone = parse_name_attr(attrs[KZNL_ATTR_QUERY_SERVER_ZONE])
        else:
            server_zone = None
        if attrs.has_key(KZNL_ATTR_SVC_NAME):
            service = parse_name_attr(attrs[KZNL_ATTR_SVC_NAME])
        else:
            service = None
        if attrs.has_key(KZNL_ATTR_DPT_NAME):
            dispatcher = parse_name_attr(attrs[KZNL_ATTR_DPT_NAME])
        else:
            dispatcher = None

        return KZorpQueryReplyMessage(client_zone, server_zone, service, dispatcher)

    def __str__(self):
        if self.client_zone:
            client_zone = self.client_zone
        else:
            client_zone = "not found"
        if self.server_zone:
            server_zone = self.server_zone
        else:
            server_zone = "not found"
        if self.service:
            service = self.service
        else:
            service = "not found"
        if self.dispatcher:
            dispatcher = self.dispatcher
        else:
            dispatcher = "not found"

        return "Client zone: %s\nServer zone: %s\nService: %s\nDispatcher: %s" % \
               (client_zone, server_zone, service, dispatcher)

class NetlinkAttributePort(NetlinkAttribute):
    def __init__(self, type, port):
        NetlinkAttribute.__init__(self, type, data=struct.pack('>H', port))

def create_port_attr(type, port):
    return NetlinkAttributePort(type, port)

def parse_port_attr(attr):
    return attr.parse_be16()

class NetlinkAttributeProto(NetlinkAttribute):
    def __init__(self, type, proto):
        if proto != socket.IPPROTO_TCP and proto != socket.IPPROTO_UDP:
            raise NetlinkAttributeException, "not supported protocol; proto='%d'" % proto

        NetlinkAttribute.__init__(self, type, data=struct.pack('>B', proto))

class KZorpAddBindMessage(GenericNetlinkMessage):
    command = KZNL_MSG_ADD_BIND

    def __init__(self, family, instance, addr, port, proto):
        super(KZorpAddBindMessage, self).__init__(self.command, version = 1)

        self.instance = instance
        self.family = family
        self.addr = addr
        self.port = port
        self.proto = proto

        self._build_payload()

    def _build_payload(self):
        self.append_attribute(create_name_attr(KZNL_ATTR_INSTANCE_NAME, self.instance))
        self.append_attribute(create_inet_addr_attr(KZNL_ATTR_BIND_ADDR, self.family, self.addr))
        self.append_attribute(NetlinkAttributePort(KZNL_ATTR_BIND_PORT, self.port))
        self.append_attribute(NetlinkAttributeProto(KZNL_ATTR_BIND_PROTO, self.proto))

    @staticmethod
    def parse(version, data):
        attrs = NetlinkAttribute.parse(NetlinkAttributeFactory, data)

        instance = parse_name_attr(attrs[KZNL_ATTR_INSTANCE_NAME])
        proto = attrs[KZNL_ATTR_BIND_PROTO].parse_int8()

        family, address = parse_inet_addr_attr(attrs[KZNL_ATTR_BIND_ADDR])
        port = parse_port_attr(attrs[KZNL_ATTR_BIND_PORT])

        if proto != socket.IPPROTO_TCP and proto != socket.IPPROTO_UDP:
            raise NetlinkAttributeException, "invalid attribute value of protocol, protocol='%d'" % (proto, )

        return KZorpAddBindMessage(family, instance, address, port, proto)

    def __str__(self):
        return "Bind instance='%s' protocol='%s', address='%s', port='%d'" % \
               (self.instance, self.proto, socket.inet_ntop(self.family, self.addr), self.port)

class KZorpGetBindMessage(GenericNetlinkMessage):
    command = KZNL_MSG_GET_BIND

    def __init__(self, instance = None):
        super(KZorpGetBindMessage, self).__init__(self.command, version = 1)

        self.instance = instance

        self._build_payload()

    def _build_payload(self):
        if self.instance:
            self.append_attribute(create_name_attr(KZNL_ATTR_INSTANCE_NAME, self.instance))

class KZorpMessageFactory(object):
    known_classes = {
      KZNL_MSG_ADD_BIND            : KZorpAddBindMessage,
      KZNL_MSG_ADD_DISPATCHER      : KZorpAddDispatcherMessage,
      KZNL_MSG_ADD_RULE            : KZorpAddRuleMessage,
      KZNL_MSG_ADD_RULE_ENTRY      : KZorpAddRuleEntryMessage,
      KZNL_MSG_ADD_SERVICE         : KZorpAddServiceMessage,
      KZNL_MSG_ADD_SERVICE_NAT_DST : KZorpAddServiceDestinationNATMappingMessage,
      KZNL_MSG_ADD_SERVICE_NAT_SRC : KZorpAddServiceSourceNATMappingMessage,
      KZNL_MSG_ADD_ZONE            : KZorpAddZoneMessage,
      KZNL_MSG_FLUSH_BIND          : KZorpFlushBindsMessage,
      KZNL_MSG_FLUSH_DISPATCHER    : KZorpFlushDispatchersMessage,
      KZNL_MSG_FLUSH_SERVICE       : KZorpFlushServicesMessage,
      KZNL_MSG_FLUSH_ZONE          : KZorpFlushZonesMessage,
      KZNL_MSG_GET_BIND            : KZorpGetBindMessage,
      KZNL_MSG_GET_DISPATCHER      : KZorpGetDispatcherMessage,
      KZNL_MSG_GET_SERVICE         : KZorpGetServiceMessage,
      KZNL_MSG_GET_ZONE            : KZorpGetZoneMessage,
      KZNL_MSG_COMMIT              : KZorpCommitTransactionMessage,
      KZNL_MSG_START               : KZorpStartTransactionMessage,
      KZNL_MSG_QUERY               : KZorpQueryMessage,
      KZNL_MSG_QUERY_REPLY         : KZorpQueryReplyMessage,
    }

    @staticmethod
    def create(command, version, data):
        if command in KZorpMessageFactory.known_classes:
            return KZorpMessageFactory.known_classes[command].parse(version, data)

        raise NetlinkException, "Netlink message command not supported: command='%d'" % (command)

import netlink
class Handle(netlink.Handle):
    def __init__(self):
        super(Handle, self).__init__('kzorp')

    def talk(self, message, is_dump_request=False, factory=KZorpMessageFactory):
        return super(Handle, self).talk(message, is_dump_request, factory)
