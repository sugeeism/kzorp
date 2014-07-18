import netlink
import random, time
import kzorp_netlink

class Handle(netlink.Handle):
    def __init__(self):
        super(Handle, self).__init__('kzorp')

    def dump(self, message, factory=kzorp_netlink.KZorpMessageFactory):
        return super(Handle, self).talk(message, True, factory)

    def exchange(self, message, factory=kzorp_netlink.KZorpMessageFactory):
        replies = []
        for reply in self.talk(message, False, factory):
            replies.append(reply)
        reply_num = len(replies)
        if reply_num == 0:
            return None
        elif reply_num == 1:
            return replies[0]
        else:
            raise netlink.NetlinkException, "Netlink message has more than one reply: command='%d'" % (msg.command)

def exchangeMessage(h, payload):
    try:
        for reply in h.talk(payload):
            pass
    except netlink.NetlinkException as e:
        raise netlink.NetlinkException, "Error while talking to kernel; result='%s'" % (e.what)

def exchangeMessages(h, messages):
    for payload in messages:
        exchangeMessage(h, payload)

def startTransaction(h, instance_name):
    tries = 7
    wait = 0.1
    while tries > 0:
        try:
            exchangeMessage(h, kzorp_netlink.KZorpStartTransactionMessage(instance_name))
        except:
            tries = tries - 1
            if tries == 0:
                raise
            wait = 2 * wait
            time.sleep(wait * random.random())
            continue

        break

def commitTransaction(h):
    exchangeMessage(h, kzorp_netlink.KZorpCommitTransactionMessage())
