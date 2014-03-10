############################################################################
##
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
##
############################################################################

import Globals
import random
import kzorp.kzorp_netlink
from Zorp import *

def downloadServices(h):
    # download services
    kzorp.kzorp_netlink.exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushServicesMessage())

    for service in Globals.services.values():
        messages = service.buildKZorpMessage()
        kzorp.kzorp_netlink.exchangeMessages(h, messages)

def downloadDispatchers(h):
    kzorp.kzorp_netlink.exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushDispatchersMessage())

    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpMessage()
            kzorp.kzorp_netlink.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise


def downloadBindAddresses(h):
    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpBindMessage()
            kzorp.kzorp_netlink.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during bind address upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise

def createAddZoneMessageFromZone(zone):
    subnet_num = len(zone.subnets) + len(zone.hostnames)
    pname = zone.admin_parent.name if zone.admin_parent else None
    return kzorp.kzorp_netlink.KZorpAddZoneMessage(zone.name, pname, subnet_num = subnet_num)

def createAddZoneSubnetMessagesFromZoneAddresses(zone):
    add_zone_subnet_messages = []
    for subnet in zone.subnets:
        add_zone_subnet_message = kzorp.kzorp_netlink.KZorpAddZoneSubnetMessage(zone.name,
                                                                                subnet.get_family(),
                                                                                subnet.addr_packed(),
                                                                                subnet.netmask_packed())
        add_zone_subnet_messages.append(add_zone_subnet_message)
    return add_zone_subnet_messages

def downloadStaticZones(zones):
    h = kzorp.kzorp_netlink.Handle()
    kzorp.kzorp_netlink.startTransaction(h, kzorp.kzorp_netlink.KZ_INSTANCE_GLOBAL)
    try:
        for zone in sorted(zones, cmp=lambda z1, z2: cmp(z1.getDepth(), z2.getDepth())):
            kzorp.kzorp_netlink.exchangeMessages(h, (createAddZoneMessageFromZone(zone), ))
            kzorp.kzorp_netlink.exchangeMessages(h, createAddZoneSubnetMessagesFromZoneAddresses(zone))

        kzorp.kzorp_netlink.commitTransaction(h)
    except:
        h.close()
        raise

def downloadKZorpConfig(instance_name, is_master):

    random.seed()
    h = kzorp.kzorp_netlink.Handle()

    # start transaction
    kzorp.kzorp_netlink.startTransaction(h, instance_name)

    try:
        if is_master:
            downloadServices(h)
            downloadDispatchers(h)
        downloadBindAddresses(h)
        kzorp.kzorp_netlink.commitTransaction(h)
    except:
        h.close()
        raise

    Globals.kzorp_netlink_handle = h

def flushKZorpConfig(instance_name):

    random.seed()

    h = getattr(Globals, "kzorp_netlink_handle", None)
    if not h:
        h = kzorp.kzorp_netlink.Handle()

    # flush dispatchers and services
    kzorp.kzorp_netlink.startTransaction(h, instance_name)
    try:
        kzorp.kzorp_netlink.exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushDispatchersMessage())
        kzorp.kzorp_netlink.exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushServicesMessage())
        kzorp.kzorp_netlink.commitTransaction(h)
    except:
        h.close()
        raise

    h.close()

def closeKZorpHandle():
    h = getattr(Globals, "kzorp_netlink_handle", None)
    if h:
        Globals.kzorp_netlink_handle = None
        h.close()

Globals.deinit_callbacks.append(closeKZorpHandle)
