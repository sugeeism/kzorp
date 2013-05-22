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

import random
import socket

max_32_bit_value = 0xffffffff

def rnd_percent(percentage):
    return random.randint(0,100) <= percentage

class ObjectWithId(object):
    id_sequence = 0

    @classmethod
    def get_next_id(cls):
        cls.id_sequence += 1
        return cls.id_sequence

class Zone(ObjectWithId):

    def __init__(self, name, parent, subnets):
        self.id = Zone.get_next_id()
        self.name = name
        self.parent = parent
        self.subnets = subnets
        self.children = []

    def add_child_zone(self, child):
        self.children.append(child)

    def __str__(self):
        out = ['<network description="%s" id="%d" name="%s">' % (self.name, self.id, self.name)]
        for s in self.subnets:
            out.append(str(s))
        for child in self.children:
            out.append(str(child))
        out.append('</network>')
        return "\n".join(out)

class Subnet(object):

    def __init__(self, protocol=socket.AF_INET, address=None, num_mask_bits=None):
        self.protocol = protocol
        address_length = 1 if protocol == socket.AF_INET else 4
        if address is None:
            self.address = [random.randint(0, max_32_bit_value) for _ in xrange(address_length)]
            num_mask_bits = random.randint(0, address_length * 32)
        else:
            self.address = address
        self.mask_size = num_mask_bits
        self.mask = [(max_32_bit_value if bits >= 32 else max_32_bit_value ^ ((1 << (32 - bits))-1)) for bits in xrange(num_mask_bits, 0, -32)]
        self.address = [self.address[i] & mask for i, mask in enumerate(self.mask)]

class Interface(ObjectWithId):

    def __init__(self, name, subnet, group):
        self.id = Interface.get_next_id()
        self.name = name
        self.subnet = subnet
        self.group = group

def generate_zones(num_zones):
    zones = []

    for i in xrange(num_zones):
        subnets = []

        if rnd_percent(70):
            for s in xrange(random.randint(0, 8)):
                subnets.append(Subnet())

        if i > 5 and rnd_percent(90):
            parent = zones[random.randint(1, i - 1)]
        else:
            parent = None

        zones.append(Zone("zone%d" % (i + 1, ), parent, subnets))

    for zone in zones:
        if zone.parent:
            zone.parent.add_child_zone(zone)

    return zones

def generate_interfaces(num_interfaces):
    interfaces = []

    interfaces.append(Interface("lo", Subnet(address=[0x7f000001], num_mask_bits=8), 0))

    for i in xrange(num_interfaces):
        subnet = Subnet()
        interfaces.append(Interface("eth%d" % i, subnet, random.randint(0, 10)))

    return interfaces

#########################################################################
#########################################################################

def cs_struct_initializer(items=[], indent_level=0):
    return (
        '{' +
        (('\n'+ (indent_level + 1) * '  ' + (',\n' + (indent_level + 1) * '  ').join(items) + '\n' + indent_level * '  ') if items else '') +
        '}'
    )

def cs_define_zones(zones, indent_level=0):
    return 'struct kz_zone zone[] = ' + cs_struct_initializer(
        [
            'KZ_ZONE_HEAD_INITIALIZER'
            if zone.parent is None else
            'KZ_ZONE_INITIALIZER(zone[%d])' % zones.index(zone.parent)
            for zone in zones
        ],
        indent_level
    ) + ';'

def cs_sample_from_array(name, num_items, count):
    return ', '.join([name + ('[%d]' % i) for i in random.sample(xrange(num_items), count)])

def cs_protocol():
    protocol_rates = [ ('TCP', 45), ('UDP', 45), ('ICMP', 10) ]
    distribution = protocol_rates[0:1]
    for rate in protocol_rates[1:]:
        distribution.append((rate[0], distribution[-1][1] + rate[1]))
    rnd = random.randint(0, distribution[-1][1])
    for item in distribution:
        if rnd <= item[1]:
            return 'IPPROTO_' + item[0]

def cs_port_ranges(num_ranges):
    points = random.sample(xrange(1,0x10000), 2 * num_ranges)
    points.sort()
    return ', '.join(['{ %d, %d }' % (points[2 * i], points[2 * i + 1]) for i in xrange(num_ranges) ])

def cs_subnet(subnet):
    initializer = '{ %s }' if subnet.protocol == socket.AF_INET else '{.s6_addr32 = { %s }}'
    return ('{ %d, { %s, %s } }' % (subnet.mask_size, initializer, initializer)) % (
        ', '.join(['0x%.8x' % value for value in subnet.address]),
        ', '.join(['0x%.8x' % value for value in subnet.mask]),
    )

def cs_define_subnets(subnets, indent_level=0):
    suffix = '' if not subnets or subnets[0].protocol == socket.AF_INET else '6'
    return 'struct subnet' + suffix + ' subnet' + suffix + '[] = ' + cs_struct_initializer(
        [cs_subnet(subnet) for subnet in subnets],
        indent_level
    ) + ';'

def cs_rule_entry(name, items):
    return 'KZ_RULE_ENTRY_INITIALIZER( ' + ', '.join([name] + items) + ' )'

def cs_rule(interfaces, num_interfaces, num_port_ranges, zones, num_zones, num_protocols, subnets, num_subnets, subnets6, num_subnets6, indent_level=0):
    rule = []

    count = random.randint(0, num_interfaces)
    interface_sample = random.sample(interfaces, count)
    if count:
        rule.append(cs_rule_entry('ifname', ['"%s"' % interface.name for interface in interface_sample]))

    count = random.randint(0, num_interfaces)
    interface_sample = random.sample(interfaces, count)
    if interface_sample:
        rule.append(cs_rule_entry('ifgroup', [str(interface.group) for interface in interface_sample]))

    count = random.randint(0, num_port_ranges)
    if(count):
        rule.append(cs_rule_entry('src_port', [cs_port_ranges(count)]))

    count = random.randint(0, num_port_ranges)
    if(count):
        rule.append(cs_rule_entry('dst_port', [cs_port_ranges(count)]))

    count = random.randint(0, num_zones)
    if(count):
        rule.append(cs_rule_entry('src_zone', [cs_sample_from_array('&zone', len(zones), count)]))

    count = random.randint(0, num_zones)
    if(count):
        rule.append(cs_rule_entry('dst_zone', [cs_sample_from_array('&zone', len(zones), count)]))

    count = random.randint(0, num_protocols)
    if(count):
        rule.append(cs_rule_entry('proto', [cs_protocol() for i in xrange(count)]))

    count = random.randint(0, num_subnets)
    if(count):
        rule.append(cs_rule_entry('src_in_subnet', [cs_sample_from_array('subnet', len(subnets), count)]))

    count = random.randint(0, num_subnets)
    if(count):
        rule.append(cs_rule_entry('dst_in_subnet', [cs_sample_from_array('subnet', len(subnets), count)]))

    count = random.randint(0, num_subnets6)
    if(count):
        rule.append(cs_rule_entry('src_in6_subnet', [cs_sample_from_array('subnet6', len(subnets), count)]))

    count = random.randint(0, num_subnets6)
    if(count):
        rule.append(cs_rule_entry('dst_in6_subnet', [cs_sample_from_array('subnet6', len(subnets), count)]))

    return cs_struct_initializer(rule, indent_level)

def cs_define_rules(num_rules, interfaces, num_interfaces, num_port_ranges, zones, num_zones, num_protocols, subnets, num_subnets, subnets6, num_subnets6, indent_level=0):
    return 'struct kz_dispatcher_n_dimension_rule rules[] = ' + cs_struct_initializer(
        [
            cs_rule(interfaces, num_interfaces, num_port_ranges, zones, num_zones, num_protocols, subnets, num_subnets, subnets6, num_subnets6, indent_level + 1)
            for _ in xrange(num_rules)
        ],
        indent_level
    ) + ';'

def cs_input(interfaces, num_zones, num_subnets4, num_subnet6, indent_level=0):
    interface = random.choice(interfaces)
    (suffix, num_subnets) = ('', num_subnets4) if rnd_percent(90) else ('6', num_subnets6)
    address_format = '{ .in%(suffix)s = subnet%(suffix)s' % {'suffix': suffix} + '[%d].addr.addr }'
    return cs_struct_initializer(
        [
            '.iface = { .name = "%s", .group = %d }' % (interface.name, interface.group),
            '.l3proto = AF_INET%s' % suffix,
            '.src_addr = ' + (address_format % random.randint(0, num_subnets - 1)),
            '.dst_addr = ' + (address_format % random.randint(0, num_subnets - 1)),
            '.l4proto = %s' % cs_protocol(),
            '.src_port = %d' % random.randint(1, 0x10000),
            '.dst_port = %d' % random.randint(1, 0x10000),
            '.src_zone = zone[%d]' % random.randint(0, num_zones - 1),
            '.dst_zone = zone[%d]' % random.randint(0, num_zones - 1)
        ],
        indent_level
    )

def cs_define_inputs(num_inputs, interfaces, num_zones, num_subnets4, num_subnet6, indent_level=0):
    return 'struct input in[] = ' + cs_struct_initializer(
        [
            cs_input(interfaces, num_zones, num_subnets4, num_subnet6, indent_level + 1)
            for _ in xrange(num_inputs)
        ],
        indent_level
    ) + ';'

def cs_define_interfaces(interfaces, indent_level=0):
    return 'struct net_device interface[] = ' + cs_struct_initializer(
        [
            '{ .name = "%s", .group = %d }' % (interface.name, interface.group)
            for interface in interfaces
        ],
        indent_level
    ) + ';'

#########################################################################

num_zones = 500
num_interfaces = 50
num_subnets = 500
num_subnets6 = 250

num_rules = 0
num_inputs = 0

num_max_sample_interfaces = num_interfaces / 5
num_max_port_ranges = 5
num_max_sample_zones = num_zones / 10
num_max_protocols = 2
num_max_sample_subnets = num_subnets / 20
num_max_sample_subnets6 = num_subnets6 / 25

random.seed(12)
zones = generate_zones(num_zones)
interfaces = generate_interfaces(num_interfaces)
subnets = [Subnet() for _ in xrange(num_subnets)]
subnets6 = [Subnet(socket.AF_INET6) for _ in xrange(num_subnets6)]

print '// Generated by kzorp_rule_generator.py'
if 1:
    print cs_define_interfaces(interfaces)
    print
    print cs_define_zones(zones)
    print
    print cs_define_subnets(subnets)
    print
    print cs_define_subnets(subnets6)
    print
    print cs_define_rules(
        num_rules=num_rules,
        interfaces=interfaces,
        num_interfaces=num_max_sample_interfaces,
        num_port_ranges=num_max_port_ranges,
        zones=zones,
        num_zones=num_max_sample_zones,
        num_protocols=num_max_protocols,
        subnets=subnets,
        num_subnets=num_max_sample_subnets,
        subnets6=subnets6,
        num_subnets6=num_max_sample_subnets6
    )
    print
    print cs_define_inputs(num_inputs, interfaces, num_zones, num_subnets, num_subnets6)

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
