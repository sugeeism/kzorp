# This is a 'policy.py' file for testing zorp - kzorp communication.
#
# Start zorp with '/usr/lib/zorp/zorp -a test_instance -l -F -v 6'
# and check the output of 'kzorp -s -z -d'.

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
import socket
from Zorp.Core import *
from Zorp.Plug import *

Zorp.firewall_name = 'zorp@test'

# Test definitions of zones:
InetZone("inside", ["11.22.33.0/24", "a1b2:c3d4:e5f6::/48"])
InetZone("manager", ["11.22.33.1/32"],admin_parent="inside")
InetZone("internet", ["0.0.0.0/0", "::/0"])
InetZone("outside", ["44.55.66.252/30"], admin_parent="internet")

# Definitions of NAT policies for PFService:
NATPolicy(name="test_snat", nat=GeneralNAT(mapping=((InetSubnet("11.22.33.0/24"), InetSubnet("165.90.85.170/32"), InetSubnet("44.55.0.0/16")), )), cacheable=FALSE)
NATPolicy(name="test_dnat", nat=GeneralNAT(mapping=((InetSubnet("12.23.34.0/24"), InetSubnet("90.85.165.171/32"), InetSubnet("45.54.0.0/16")), )), cacheable=TRUE)

class TestProxy(PlugProxy):

    def config(self):
        Proxy.config(self)
        self.transparent_mode = TRUE

def test_instance():
    Service("run_service",TestProxy);
    # Test definitions of services:
    Service("test_service1", TestProxy)
    PFService("test_service2", router=DirectedRouter(SockAddrInet("11.22.33.44", 55)), snat_policy="test_snat", dnat_policy="test_dnat")
    #DenyService("test_service3")
    Service("test_service3",TestProxy)

    Rule(
       service="run_service",
       src_zone="inside",
       dst_zone="outside",
       dst_port="4567"
    )
    # Test attribute setting with atomic values:
    Rule(
        service="test_service1",
        dst_zone="inside",
#        dst_ifgroup=31,
#        dst_iface="if1",
        dst_subnet="12.34.56.78/32",
        src_zone="outside",
        src_subnet="176.85.127.0/24",
        dst_port=1234,
        src_port=5678,
        proto=1,
        ifgroup=999,
        iface="if2",
#        reqid=165
    )

    # Test IPv6 attribute setting with atomic values:
    Rule(
        service="test_service3",
        src_subnet="9876:5432::1abc:de80/121",
        dst_subnet="abcd:ef12:3456:789a:bcde:f123:4567:89a0/124"
    )

    # Test attribute setting with list:
    Rule(
        service="test_service2",
        dst_zone=["inside", "outside"],
#        dst_ifgroup=[5, 7, 11],
#        dst_iface=["if1", "if2"],
        dst_subnet=["1.2.3.4/32", "45.67.89.0/24", "aaaa:bbbb:cccc:dddd:eeee::/80", "1111:2222:3333::4440:0/108"],
        src_zone=["outside", "inside"],
        src_subnet=["176.85.127.0/24", "95.126.223.192/26", "a5a5::5a5a:0:0:0/80", "::fafa:0:5f5f:0:0/96"],
        dst_port=[PortRange(12, 34), 5678, 32767, 16384],
        src_port=[11111, 22222],
        proto=[socket.IPPROTO_TCP, socket.IPPROTO_UDP],
        ifgroup=[98, 76, 54],
        iface=["if3", "if4"],
#        reqid=[24681357, 10203040]
    )
