#
#
# Copyright (C) 2006-2012, BalaBit IT Ltd.
# This program/include file is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3 of the License, or
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
InetZone('internet', ['0.0.0.0/0'],
    inbound_services=["*"],
    outbound_services=["*"])

InetZone('enternet', ['1.2.3.4/16'],
    inbound_services=[
        "service", "pfservice"],
    outbound_services=[
        "service", "pfservice"])

def generate_rules():
    gen_rules = []
    for i in range(100000):
        gen_rules.append({ 'iface': ("eth0", "eth1"), 'ifgroup': (2, 9), 'proto': socket.IPPROTO_TCP, 'src_port': 80, 'dst_port': "12,23:24",
          'src_subnet': ('10.0.0.0/8', '1.2.3.5/24'), 'src_zone': ('internet', 'internet'),
          'dst_subnet': '2.3.4.5', 'dst_zone': 'internet', 'service': 'pityuka'})

    NDimensionDispatcher(bindto=DBSockAddr(SockAddrInet('0.0.0.0', 50000), ZD_PROTO_TCP), rules=tuple(gen_rules))

def plug() :
    PFService(name="pityuka", router=TransparentRouter(forge_addr=TRUE))
    generate_rules()
