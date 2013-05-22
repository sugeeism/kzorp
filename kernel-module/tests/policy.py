#
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
#

from  Zorp.Core import  *
from  Zorp.Proxy import  *
from  Zorp.Plug import  *

"""Fallback zone"""
InetZone('internet', ['0.0.0.0/0'])

InetZone('enternet', ['1.2.3.4/16'])


def plug() :
    PFService(name="pityuka", router=TransparentRouter(forge_addr=TRUE))
    PFService(name="pfservice", router=TransparentRouter(forge_addr=TRUE))

    NDimensionDispatcher(bindto=DBSockAddr(SockAddrInet('0.0.0.0', 50010), ZD_PROTO_TCP), rules=(
      { 'iface': ("eth0", "eth1"), 'ifgroup': (2, 9), 'proto': socket.IPPROTO_TCP, 'src_port': 80, 'dst_port': "12,23:24",
        'src_subnet': ('10.0.0.0/8', '1.2.3.5/24'), 'src_zone': ('internet', 'internet'),
        'dst_subnet': '2.3.4.5', 'dst_zone': 'internet', 'service': 'pityuka', 'rule_id' : 452},
      { 'iface' : "eth0", 'dst_zone' : "internet", 'service' : 'pityuka' }
      )
      )

    NDimensionDispatcher(bindto=DBSockAddr(SockAddrInet('0.0.0.0', 50011), ZD_PROTO_TCP), rules=(
      { 'iface': 'eth0', 'ifgroup': 2, 'proto': socket.IPPROTO_TCP, 'src_port': 80, 'dst_port': 12,
        'src_subnet': '1.2.3.4', 'src_zone': 'internet',
        'dst_subnet': '1.2.3.4', 'dst_zone': 'internet', 'service': 'pityuka'},
      { 'iface' : "eth0", 'service' : 'pityuka' },
      { 'iface' : ("eth0"), 'service' : 'pityuka' },
      { 'iface' : ("eth0", 'eth1'), 'service' : 'pityuka' },
      { 'ifgroup' : 2, 'service' : 'pityuka', 'rule_id' : 20 },
      { 'ifgroup' : (2,3,4), 'service' : 'pityuka' },
      { 'proto' : socket.IPPROTO_TCP, 'service' : 'pityuka' },
      { 'proto' : socket.IPPROTO_UDP, 'service' : 'pityuka' },
      { 'src_port' : 80, 'service' : 'pityuka' },
      { 'src_port' : '90', 'service' : 'pityuka' },
      { 'src_port' : '100:110', 'service' : 'pityuka' },
      { 'src_port' : '120, 121:122, 123', 'service' : 'pityuka' },
      { 'dst_port' : 80, 'service' : 'pityuka' },
      { 'dst_port' : '90', 'service' : 'pityuka' },
      { 'dst_port' : '100:110', 'service' : 'pityuka' },
      { 'dst_port' : '120, 121:122, 123', 'service' : 'pityuka' },
      { 'src_subnet' : '1.2.3.4', 'service' : 'pityuka' },
      { 'src_subnet' : '1.2.3.5/32', 'service' : 'pityuka' },
      { 'src_subnet' : '10.1.1.1/8', 'service' : 'pityuka' },
      { 'src_subnet' : '172.16.1.1/16', 'service' : 'pityuka' },
      { 'src_subnet' : '192.168.1.1/24', 'service' : 'pityuka' },
      { 'src_subnet' : ('192.168.2.1/24'), 'service' : 'pityuka' },
      { 'src_subnet' : ('192.168.3.1/24', '10.2.3.4/9', '172.16.17.18/17'), 'service' : 'pityuka' },
      { 'dst_subnet' : '1.2.3.4', 'service' : 'pityuka' },
      { 'dst_subnet' : '1.2.3.5/32', 'service' : 'pityuka' },
      { 'dst_subnet' : '10.1.1.1/8', 'service' : 'pityuka' },
      { 'dst_subnet' : '172.16.1.1/16', 'service' : 'pityuka' },
      { 'dst_subnet' : '192.168.1.1/24', 'service' : 'pityuka' },
      { 'dst_subnet' : ('192.168.2.1/24'), 'service' : 'pityuka' },
      { 'dst_subnet' : ('192.168.3.1/24', '10.2.3.4/9', '172.16.17.18/17'), 'service' : 'pityuka' },
      { 'src_zone' : 'internet', 'service' : 'pityuka' },
      { 'src_zone' : ('internet'), 'service' : 'pityuka' },
      { 'src_zone' : ('internet', 'enternet'), 'service' : 'pityuka' },
      { 'dst_zone' : 'internet', 'service' : 'pityuka' },
      { 'dst_zone' : ('internet'), 'service' : 'pityuka' },
      { 'dst_zone' : ('internet', 'enternet'), 'service' : 'pityuka' },
      )
      )

def plug2() :
    PFService(name="patyuka", router=TransparentRouter(forge_addr=TRUE))

    NDimensionDispatcher(bindto=DBSockAddr(SockAddrInet('0.0.0.0', 50012), ZD_PROTO_TCP), rules=(
      { 'iface': ("eth0", "eth1"), 'service': 'patyuka'},
      )
      )
