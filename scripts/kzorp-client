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
import optparse
import sys
import types
import socket
import kzorp.kzorp_netlink as kznl

AttributeRequiredError = "required attribute missing"

def inet_ntoa(a):
    return "%s.%s.%s.%s" % ((a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff)

def size_to_mask(family, size):
    if family == socket.AF_INET:
        max_size = 32
    elif family == socket.AF_INET6:
        max_size = 128
    else:
        raise ValueError, "address family not supported; family='%d'" % family

    if size > max_size:
        raise ValueError, "network size is greater than the maximal size; size='%d', max_size='%d'" % (size, max_size)

    packed_mask = ''
    actual_size = 0
    while actual_size + 8 < size:
        packed_mask += '\xff'
        actual_size = actual_size + 8

    if actual_size <= size:
        packed_mask += chr((0xff << (8 - (size - actual_size))) & 0xff)
        actual_size = actual_size + 8

    while actual_size < max_size:
        packed_mask += '\x00'
        actual_size = actual_size + 8

    return socket.inet_ntop(family, packed_mask)

class DumpBase():
    def __init__(self, quiet, msg):
        self.quiet = quiet
        self.msg = msg
        self.replies = []

    replies = []
    def dump(self):
        try:
            handle = kznl.Handle()
            for reply in handle.talk(self.msg, True):
                self.replies.append(reply)
                if self.quiet:
                    pass
                else:
                    print str(reply)
        except kznl.NetlinkException as e:
            res = int(e.detail)
            sys.stderr.write("Dump failed: result='%d' error='%s'\n" % (res, os.strerror(-res)))
            return 1

        return 0

class DumpZones(DumpBase):
    def __init__(self, quiet):
        DumpBase.__init__(self, quiet, kznl.KZorpGetZoneMessage())

class DumpServices(DumpBase):
    def __init__(self, quiet):
        DumpBase.__init__(self, quiet, kznl.KZorpGetServiceMessage())

class DumpDispatchers(DumpBase):
    def __init__(self, quiet):
        DumpBase.__init__(self, True, kznl.KZorpGetDispatcherMessage())
        self.__real_quiet = quiet

    @staticmethod
    def __rule_entries_to_str(rule_entries):
        dimensions = [
            (kznl.KZNL_ATTR_N_DIMENSION_REQID    ,   'reqid'),
            (kznl.KZNL_ATTR_N_DIMENSION_IFACE    ,   'src_iface'),
            (kznl.KZNL_ATTR_N_DIMENSION_IFGROUP  ,   'src_ifgroup'),
            (kznl.KZNL_ATTR_N_DIMENSION_PROTO    ,   'proto'),
            (kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT ,   'src_port'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_PORT ,   'dst_port'),
            (kznl.KZNL_ATTR_N_DIMENSION_SRC_IP   ,   'src_subnet'),
            (kznl.KZNL_ATTR_N_DIMENSION_SRC_IP6  ,   'src_subnet'),
            (kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE ,   'src_zone'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_IP   ,   'dst_subnet'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_IP6  ,   'dst_subnet'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_IFACE,   'dst_iface'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_IFGROUP, 'dst_ifgroup'),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE ,   'dst_zone')
        ]

        entries = dict(rule_entries)

        for ip in [
            (kznl.KZNL_ATTR_N_DIMENSION_SRC_IP, kznl.KZNL_ATTR_N_DIMENSION_SRC_IP6),
            (kznl.KZNL_ATTR_N_DIMENSION_DST_IP, kznl.KZNL_ATTR_N_DIMENSION_DST_IP6)
        ]:
            if ip[0] in rule_entries and ip[1] in rule_entries:
                entries[ip[0]] += rule_entries[ip[1]]
                del entries[ip[1]]

        res = ""
        for dim_type in dimensions:
            if dim_type[0] in entries:
                res += "           %s=%s\n" % (dim_type[1], entries[dim_type[0]])
        return res

    def dump(self):
        DumpBase.dump(self)
        if not self.__real_quiet:
            rule_entries = {}
            for reply in self.replies:
                if reply.command == kznl.KZorpAddRuleEntryMessage.command:
                    reply.aggregate_rule_entries(rule_entries)
                elif reply.command == kznl.KZorpAddRuleMessage.command:
                    print DumpDispatchers.__rule_entries_to_str(rule_entries)
                    rule_entries = {}
                    print reply
                else:
                    print reply

            res = DumpDispatchers.__rule_entries_to_str(rule_entries)
            if res:
                print res

class DumpBinds(DumpBase):
    def __init__(self, quiet):
        DumpBase.__init__(self, quiet, kznl.KZorpGetBindMessage())

def upload_zones(fname):

    def parse_range(r):
        if r.count("/") == 0:
            # simple IP address
            addr = r
            mask = None
        else:
            # IP subnet
            (addr, mask) = r.split('/', 1)

        family = socket.AF_INET
        try:
            socket.inet_pton(family, addr)
        except socket.error:
            family = socket.AF_INET6
            socket.inet_pton(family, addr)

        if mask == None:
            if family == socket.AF_INET:
                mask = 32
            elif family == socket.AF_INET6:
                mask = 128

        mask = size_to_mask(family, int(mask))
        return (family, socket.inet_pton(family, addr), socket.inet_pton(family, mask))

    def process_line(handle, line):
        # skip comments
        if line.startswith("#"):
            return

        zone, parent, r = line.split(";")

        zone = zone.strip('"')
        parent = parent.strip('"')
        if parent == "":
            parent = None

        ranges = r.split(",")
        if len(ranges) <= 1:
            if ranges == [""]:
                ranges = []
            else:
                ranges = [r]

        # we send the "parent" first
        handle.send(kznl.KZorpAddZoneMessage(zone, address=None, mask=None, uname=zone, pname=parent))
        # then the rest
        for i in xrange(len(ranges)):
            uname = zone + "-#%d" % (i,)
            family, addr, mask = parse_range(ranges[i])
            handle.send(kznl.KZorpAddZoneMessage(zone, family=family, address=addr, mask=mask, uname=uname, pname=zone))

    handle = kznl.Handle()
    handle.send(kznl.KZorpStartTransactionMessage(kznl.KZ_INSTANCE_GLOBAL))
    handle.send(kznl.KZorpFlushZonesMessage())

    # process each zone
    f = file(fname)
    while 1:
        line = f.readline()
        if not line: break

        line = line.strip()

        try:
            process_line(handle, line)
        except Exception, e:
            sys.stderr.write("Error while processing the following line: %s\n%s\n" % (e, line))
            return 1

    handle.send(kznl.KZorpCommitTransactionMessage())

    return 0

def evaluate_option_parser_cb(option, opt_str, value, parser):
    assert value is None
    value = []
    if len(parser.rargs) < 6 or len(parser.rargs) > 7:
        raise optparse.OptionValueError("-e option requires 6 or 7 arguments")

    for arg in parser.rargs:
        # stop on --foo like options
        if arg[:2] == "--" and len(arg) > 2:
            break

        # stop on -a
        if arg[:1] == "-" and len(arg) > 1:
            break
        value.append(arg)

    del parser.rargs[:len(value)]
    setattr(parser.values, option.dest, value)

def evaluate(parser, args, quiet):
    EVAL_ARG_NUM_PROTO    = 0
    EVAL_ARG_NUM_SRC_IP   = 1
    EVAL_ARG_NUM_SRC_PORT = 2
    EVAL_ARG_NUM_DST_IP   = 3
    EVAL_ARG_NUM_DST_PORT = 4
    EVAL_ARG_NUM_IFACE    = 5
    EVAL_ARG_NUM_REQID    = 6
    EVAL_ARG_NUM          = 7

    optional_argument_num = len([EVAL_ARG_NUM_REQID, ])

    def parse_ip(parser, ip, description):
        try:
            return (socket.AF_INET, socket.inet_pton(socket.AF_INET, ip))
        except socket.error:
            try:
                return (socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ip))
            except socket.error:
                parser.error("invalid %s ip: %s" % (description, ip))

    def parse_num(parser, num_str, max_num_bits, description):
        try:
            num = int(num_str)
            if 0 < num < 2 ** max_num_bits:
                return num
            else:
                raise ValueError, ""
        except ValueError:
            parser.error("invalid %s: %s" % (description, num_str))

    def parse_reqid(parser, reqid, description):
        return parse_num(parser, reqid, 32, description)

    def parse_port(parser, port, description):
        return parse_num(parser, port, 16, description)

    def parse_proto(parser, proto):
        if proto.lower() == "tcp":
            return socket.IPPROTO_TCP
        elif proto.lower() == "udp":
            return socket.IPPROTO_UDP
        else:
            parser.error('protocol must be "tcp" or "udp"')

    if len(args) < EVAL_ARG_NUM - optional_argument_num:
        parser.error('evaluate requires at least %d parameters', EVAL_ARG_NUM - optional_argument_num)

    kws = {}
    kws['proto'] = parse_proto(parser, args[EVAL_ARG_NUM_PROTO])

    kws['saddr_str'] = args[EVAL_ARG_NUM_SRC_IP]
    (sfamily, saddr) = parse_ip(parser, kws['saddr_str'], "client")
    kws['family'] = sfamily
    kws['saddr'] = saddr

    kws['sport'] = parse_port(parser, args[EVAL_ARG_NUM_SRC_PORT], "client port")

    kws['daddr_str'] = args[EVAL_ARG_NUM_DST_IP]
    (dfamily, daddr) = parse_ip(parser, kws['daddr_str'], "server")
    kws['daddr'] = daddr

    kws['dport'] = parse_port(parser, args[EVAL_ARG_NUM_DST_PORT], "server port")

    kws['iface'] = args[EVAL_ARG_NUM_IFACE]
    if len(args[EVAL_ARG_NUM_IFACE]) > 15:
        parser.error('invalid interface name (>15 characters)')

    if len(args) == EVAL_ARG_NUM:
        kws['reqid'] = parse_reqid(parser, args[EVAL_ARG_NUM_REQID], "request id")

    if sfamily != dfamily:
        parser.error("family of source and destination address is not the same")

    if not quiet:
        eval_str = "evaluating %(saddr_str)s:%(sport)s -> %(daddr_str)s:%(dport)s on %(iface)s" % kws
        if 'reqid' in kws:
            eval_str += " with request id is %s" % (kws['reqid'])
        print eval_str

    del kws['saddr_str']
    del kws['daddr_str']

    handle = kznl.Handle()
    query_msg = kznl.KZorpQueryMessage(**kws)
    for reply in handle.talk(query_msg, False):
        print str(reply)

def main(args):
    option_list = [
                     optparse.make_option("-z", "--zones",
                                          action="store_true", dest="zones",
                                          default=False,
                                          help="dump KZorp zones "
                                               "[default: %default]"),
                     optparse.make_option("-s", "--services",
                                          action="store_true", dest="services",
                                          default=False,
                                          help="dump KZorp services "
                                               "[default: %default]"),
                     optparse.make_option("-d", "--dispatchers",
                                          action="store_true", dest="dispatchers",
                                          default=False,
                                          help="dump KZorp dispatchers "
                                               "[default: %default]"),
                     optparse.make_option("-b", "--binds",
                                          action="store_true", dest="binds",
                                          default=False,
                                          help="dump KZorp instance bind parameters"
                                               "[default: %default]"),
                     optparse.make_option("-e", "--evaluate",
                                          dest="evaluate",
                                          action="callback",
                                          default=None,
                                          callback=evaluate_option_parser_cb,
                                          help="evaluate "
                                               "arguments: <protocol> <client address> <client port> <server address> <server port> <interface name> [request id]"),
                     optparse.make_option("-q", "--quiet",
                                          action="store_true", dest="quiet",
                                          default=False,
                                          help="quiet operation "
                                               "[default: %default]"),
                     optparse.make_option("-u", "--upload",
                                          action="store", type="string", dest="upload",
                                          default=None,
                                          help="upload KZorp zone structure from file "
                                               "[default: %default]")
                  ]

    parser = optparse.OptionParser(option_list=option_list, prog="kzorp", usage = "usage: %prog [options]")
    (options, args) = parser.parse_args()

    if (options.zones or options.services or options.dispatchers or options.binds or options.upload != None or options.evaluate != None) == False:
        parser.error("at least one option must be set")

    if os.getuid() != 0:
        sys.stderr.write("kzorp must be run as root\n")
        return 2

    res = 3
    try:
        if options.zones:
            dump_zones = DumpZones(options.quiet)
            res = dump_zones.dump()
        if options.services:
            dump_services = DumpServices(options.quiet)
            res = dump_services.dump()
        if options.dispatchers:
            dump_dispatchers = DumpDispatchers(options.quiet)
            res = dump_dispatchers.dump()
        if options.binds:
            dump_binds = DumpBinds(options.quiet)
            res = dump_binds.dump()
        if options.upload:
            res = upload_zones(options.upload)
        if options.evaluate:
            res = evaluate(parser, options.evaluate, options.quiet)
    except socket.error, e:
        if e[0] == 111:
            sys.stderr.write("KZorp support not present in kernel\n")
            return 2
        raise

    return res

if __name__ == "__main__":
    res = main(sys.argv)
    sys.exit(res)
