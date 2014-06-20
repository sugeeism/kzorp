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
import random, time, socket, errno, functools
import kzorp.kzorp_netlink
from Zorp import *
from Zone import Zone

def exchangeMessage(h, payload):
    try:
        for reply in h.talk(payload):
            pass
    except kzorp.netlink.NetlinkException as e:
        raise kzorp.netlink.NetlinkException, "Error while talking to kernel; result='%s'" % (e.what())

def exchangeMessages(h, messages):
    for payload in messages:
        exchangeMessage(h, payload)

def startTransaction(h, instance_name):
    tries = 7
    wait = 0.1
    while tries > 0:
        try:
            exchangeMessage(h, kzorp.kzorp_netlink.KZorpStartTransactionMessage(instance_name))
        except:
            tries = tries - 1
            if tries == 0:
                raise
            wait = 2 * wait
            time.sleep(wait * random.random())
            continue

        break

def commitTransaction(h):
    exchangeMessage(h, kzorp.kzorp_netlink.KZorpCommitTransactionMessage())

def downloadServices(h):
    # download services
    exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushServicesMessage())

    for service in Globals.services.values():
        messages = service.buildKZorpMessage()
        exchangeMessages(h, messages)

def downloadZones(h):
    def walkZones(messages, zone, children):
        messages.extend(zone.buildKZorpMessage())
        for child in children.get(zone.name, []):
            walkZones(messages, child, children)

    # download zones
    exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushZonesMessage())

    # build children hash
    children = {}
    for zone in Zone.zones.values():
        if zone.admin_parent:
            children.setdefault(zone.admin_parent.name, []).append(zone)

    for zone in Zone.zones.values():
        if not zone.admin_parent:
            # tree root
            messages = []
            walkZones(messages, zone, children)
            exchangeMessages(h, messages)

def downloadDispatchers(h):
    exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushDispatchersMessage())

    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpMessage()
            exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise


def downloadBindAddresses(h):
    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpBindMessage()
            exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during bind address upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise

def downloadKZorpConfig(instance_name, is_master):

    random.seed()
    h = kzorp.kzorp_netlink.Handle()

    # start transaction
    startTransaction(h, instance_name)

    try:
        if is_master:
            downloadServices(h)
            downloadZones(h)
            downloadDispatchers(h)
        downloadBindAddresses(h)
        commitTransaction(h)
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
    startTransaction(h, instance_name)
    try:
        exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushDispatchersMessage())
        exchangeMessage(h, kzorp.kzorp_netlink.KZorpFlushServicesMessage())
        commitTransaction(h)
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
