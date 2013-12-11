
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
from KZorpBaseTestCaseDispatchers import KZorpBaseTestCaseDispatchers
from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
import kzorp.netlink as netlink
import kzorp.kzorp_netlink as kznl
import errno
import socket
import testutil

class KZorpTestCaseDispatchers(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):
    _dispatchers = [
                     { 'name' : 'n_dimension', 'num_rules' : 1,
                       'rules' : [
                                   { 'rule_id' : 1, 'service' : 'A_A',
                                     'entry_nums' :
                                                 {
                                                   kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 2,
                                                   kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 2

                                                 },
                                     'entry_values' :
                                                 {
                                                   kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(12,12), (23, 44)],
                                                   kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ["AAA", "ZZZ"]
                                                 }
                                   }
                                 ]
                     },
                     { 'name' : 'n_dimension_with_rules', 'num_rules' : 3,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                     'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 1 },
                                     'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)] }
                                   },
                                   { 'rule_id'      : 2, 'service' : 'A_A',
                                     'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 3 },
                                     'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : ['eth0', 'eth1'], kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(3,3), (4,4), (50000,65534)]}
                                   },
                                   { 'rule_id'      : 3, 'service' : 'A_A',
                                     'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 4, kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 2 },
                                     'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(1,2)], kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AAA', 'AZA', 'AA', 'A'], kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(10000,10000), (20000, 30000)] }
                                   }
                                 ]
                     },
                     { 'name' : 'n_dimension_with_ALL_rules', 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'Z_Z',
                                     'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2, kznl.KZNL_ATTR_N_DIMENSION_PROTO : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : 2, kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 3, kznl.KZNL_ATTR_N_DIMENSION_DST_IP : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, kznl.KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                     'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : ['eth4', 'eth2'], kznl.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)], kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4', '2.3.4.5/24'], kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], kznl.KZNL_ATTR_N_DIMENSION_DST_IP : ['3.4.5.6/16', '4.5.6.7/8'], kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 'AAA', kznl.KZNL_ATTR_N_DIMENSION_IFGROUP : [1]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_IP : 3, kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 2, kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, kznl.KZNL_ATTR_N_DIMENSION_PROTO : 1, kznl.KZNL_ATTR_N_DIMENSION_IFACE : 3 },
                                     'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AZA', 'ZAZ'], kznl.KZNL_ATTR_N_DIMENSION_DST_IP : ['8.7.6.5', '7.6.5.4/31', '9.8.7.6/25'], kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 'ZZ', kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : ['5.4.3.2/32', '6.5.4.3/30'], kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(66,66),(100,200)], kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(23,24), (30, 40)], kznl.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], kznl.KZNL_ATTR_N_DIMENSION_IFACE : ['eth0', 'eth1', 'eth2'] }
                                   }
                                 ]
                     }

                   ]
    _services_tmp = [
                      {'dispatcher_name' : 'n_dimension',   'name' : 'A_A', 'czone' : 'A', 'szone' : 'A'},
                      {'dispatcher_name' : 'n_dimension_2', 'name' : 'Z_Z', 'czone' : 'Z', 'szone' : 'Z'}
                    ]

    def __init__(self, *args):
        KZorpBaseTestCaseDispatchers.__init__(self, *args)
        KZorpBaseTestCaseZones.__init__(self, *args)

        self._add_dispatcher_messages = []
        self._add_dispatcher_message = None
        self._index = -1

    def setUp(self):
        self.setup_service_dispatcher(self._services_tmp, self._dispatchers)

    def tearDown(self):
        self.flush_all()
        pass

    def test_get_4k_dispatcher(self):
        services = ['A_A']
        _iface_num = 300
        _iface_list = []
        _iface_string = "abcdefghijklmno"
        for i in range(_iface_num):
            _iface_list.append(_iface_string)

        dispatchers = [{ 'name' : 'n_dimension_4k', 'num_rules' : 1,
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : _iface_num, kznl.KZNL_ATTR_N_DIMENSION_PROTO : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : 2, kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 3, kznl.KZNL_ATTR_N_DIMENSION_DST_IP : 2, kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, kznl.KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                       'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : _iface_list, kznl.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)], kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4', '2.3.4.5/24'], kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], kznl.KZNL_ATTR_N_DIMENSION_DST_IP : ['3.4.5.6/16', '4.5.6.7/8'], kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 'AAA', kznl.KZNL_ATTR_N_DIMENSION_IFGROUP : [1]},
                                     }
                                   ]
                     }]

        self.setup_service_dispatcher(services, dispatchers, False, False);
        self.send_message(kznl.KZorpGetDispatcherMessage("n_dimension_4k"), message_handler = self._get_dispatchers_message_handler)
        self._check_dispatcher_params(self._add_dispatcher_messages[0], dispatchers[0])
        self._check_ndim_params(dispatchers)
    def test_n_dimension_errors(self):
        error_dup_dispatchers=[
                            { 'name' : 'n_dimension_error', 'num_rules' : 0,
                            },

                            { 'name' : 'n_dimension_error2', 'num_rules' : 2,
                              'rules' : [{ 'rule_id' : 1, 'service' : 'A_A',
                                           'entry_nums' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : 0
                                         }
                                        ]
                            }
                          ]
        error_num_rules_dispatchers=[
                            { 'name' : 'n_dimension_error3', 'num_rules' : 1,
                              'rules' : [{ 'rule_id' : 2, 'service' : 'A_A',
                                           'entry_nums' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : 0
                                         },
                                         { 'rule_id' : 3, 'service' : 'A_A',
                                           'entry_nums' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           'errno' : -errno.EINVAL
                                         }
                                        ]
                            },
                            { 'name' : 'n_dimension_error4', 'num_rules' : 1,
                              'rules' : [{ 'rule_id' : 3, 'service' : 'A_A',
                                           'entry_nums' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                           #FIXME: this shouldbe: -errno.EEXIST
                                           'errno' : 0
                                         }
                                        ]
                            }
                          ]
        error_num_rule_entries=[
                            { 'name' : 'n_dimension_error5', 'num_rules' : 8,
                              'rules' : [{ 'rule_id' : 4, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_IFACE : ['eth4', 'eth2'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 5, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_PROTO : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP, socket.IPPROTO_UDP] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 6, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(1,1), (2,2)] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 7, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_PORT : [(3,3),(4,5)] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 8, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4', '2.3.4.5'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 9, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 10, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_IP : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_IP : ['3.4.5.6', '4.5.6.7'] },
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         },
                                         { 'rule_id' : 11, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AAA', 'AA']},
                                           'rule_entry_errnos' : [0, -errno.ENOMEM]
                                         }
                                        ]
                            }
                           ]
        error_zones_exist=[
                            { 'name' : 'n_dimension_error6', 'num_rules' : 2,
                              'rules' : [{ 'rule_id' : 12, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 'BBB' },
                                           'rule_entry_errnos' : [-errno.ENOENT]
                                         },
                                         { 'rule_id' : 13, 'service' : 'A_A',
                                           'entry_nums'   : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1 },
                                           'entry_values' : { kznl.KZNL_ATTR_N_DIMENSION_DST_ZONE : 'CCC' },
                                           'rule_entry_errnos' : [-errno.ENOENT]
                                         }
                                        ]
                            }
                          ]

        #Check add_dispatcher without starting a transaction
        dispatcher = error_dup_dispatchers[0]
        message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                          )

        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

        #check duplicated add_dispatcher
        self.start_transaction()
        message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                           )
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, 0)
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, -errno.EEXIST)
        self.end_transaction()

        #check if num_rules > number of rule_entries
        dispathcer = error_dup_dispatchers[1]
        self.start_transaction()
        message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                           dispatcher['num_rules']
                                                           )
        res = self.send_message(message_add_dispatcher, assert_on_error = False)
        self.assertEqual(res, 0)
        self.end_transaction()

        #check if num_rules < number of rule entries, check adding existing rule_id
        self.start_transaction()
        for i in range(len(error_num_rules_dispatchers)):
            dispatcher = error_num_rules_dispatchers[i]
            message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                message_add_rule = kznl.KZorpAddRuleMessage(dispatcher['name'],
                                                       rule['rule_id'],
                                                       rule['service'],
                                                       rule['entry_nums']
                                                      )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
        self.end_transaction()

        #check if entry_nums < number of entry_values
        self.start_transaction()

        for i in range(len(error_num_rule_entries)):
            dispatcher = error_num_rule_entries[i]
            message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                _max = 2
                message_add_rule = kznl.KZorpAddRuleMessage(dispatcher['name'],
                                                        rule['rule_id'],
                                                        rule['service'],
                                                        rule['entry_nums']
                                                       )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
                for i in range(_max):
                    data = {}
                    for dim_type in kznl.N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums']:
                            if dim_type in [kznl.KZNL_ATTR_N_DIMENSION_SRC_IP, kznl.KZNL_ATTR_N_DIMENSION_DST_IP, kznl.KZNL_ATTR_N_DIMENSION_SRC_IP6, kznl.KZNL_ATTR_N_DIMENSION_DST_IP6]:
                                data[dim_type] = (testutil.addr_packed(rule['entry_values'][dim_type][i]), testutil.netmask_packed(rule['entry_values'][dim_type][i]))
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    message_add_rule_entry = kznl.KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)
                    res = self.send_message(message_add_rule_entry, assert_on_error = False)
                    self.assertEqual(res, rule['rule_entry_errnos'][i])

        self.end_transaction()

        self.start_transaction()
        #check zones exist
        for i in range(len(error_zones_exist)):
            dispatcher = error_zones_exist[i]
            message_add_dispatcher = kznl.KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )
            res = self.send_message(message_add_dispatcher, assert_on_error = False)

            for rule in dispatcher['rules']:
                _max = 1
                message_add_rule = kznl.KZorpAddRuleMessage(dispatcher['name'],
                                                        rule['rule_id'],
                                                        rule['service'],
                                                        rule['entry_nums']
                                                       )
                res = self.send_message(message_add_rule, assert_on_error = False)
                if 'errno' in rule:
                    self.assertEqual(res, rule['errno'])
                for i in range(_max):
                    data = {}
                    for dim_type in kznl.N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums']:
                            if dim_type == kznl.KZNL_ATTR_N_DIMENSION_SRC_IP or dim_type == kznl.KZNL_ATTR_N_DIMENSION_DST_IP:
                                data[dim_type] = (struct.pack('I', rule['entry_values'][dim_type][i].ip), struct.pack('I', rule['entry_values'][dim_type][i].mask))
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    message_add_rule_entry = kznl.KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)
                    res = self.send_message(message_add_rule_entry, assert_on_error = False)
                    self.assertEqual(res, rule['rule_entry_errnos'][i])

        self.end_transaction()

    def test_add_dispatcher(self):
        #set up and ter down test the dispatcher addition
        num_rules = 0
        num_rule_entries = 0
        for dispatcher in self._dispatchers:
            for rule in dispatcher['rules']:
                num_rules = num_rules + 1
                _max = 0
                for name, value in rule['entry_nums'].items():
                    if _max < value:
                        _max = value
                num_rule_entries = num_rule_entries + _max

        self.check_dispatcher_num(num_rules + num_rule_entries + len(self._dispatchers))

    def test_get_dispatcher_by_name(self):
        #get a not existent dispatcher
        res = self.send_message(kznl.KZorpGetDispatcherMessage('nonexistentdispatchername'), assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

    def _get_dispatchers_message_handler(self, msg):
        self._add_dispatcher_messages.append(msg)

    def _check_ndim_params(self, dispatchers):
        rule_entry_dispatcher_name = ""
        for add_dispatcher_message in self._add_dispatcher_messages:
            attrs = add_dispatcher_message.get_attributes()

            command = add_dispatcher_message.command
            if (command == kznl.KZNL_MSG_ADD_DISPATCHER or command == kznl.KZNL_MSG_ADD_RULE):
                dispatcher_name = kznl.parse_name_attr(attrs[kznl.KZNL_ATTR_DPT_NAME])

            for i in range(len(dispatchers)):
                if command == kznl.KZNL_MSG_ADD_DISPATCHER and dispatcher_name == dispatchers[i]['name']:
                    rule_index = 0
                    self._check_dispatcher_params(add_dispatcher_message, dispatchers[i])
                    break
                elif command == kznl.KZNL_MSG_ADD_RULE and dispatcher_name == dispatchers[i]['name']:
                    self._check_add_rule_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index])
                    rule_entry_dispatcher_name = dispatcher_name
                    rule_index = rule_index + 1
                    rule_entry_index = 0
                    break
                elif command == kznl.KZNL_MSG_ADD_RULE_ENTRY and dispatchers[i]['name'] == rule_entry_dispatcher_name:
                    self._check_add_rule_entry_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index - 1], rule_entry_index)
                    rule_entry_index = rule_entry_index + 1
                    break
            else:
                self.assert_(True, "dispatcher with name %s could not find in the dump") #% self.get_dispatcher_name(add_dispatcher_message))


    def test_get_dispatcher_with_dump(self):
        #get the dump of dispatchers
        self.send_message(kznl.KZorpGetDispatcherMessage(None), message_handler = self._get_dispatchers_message_handler, dump = True)
        self._check_ndim_params(self._dispatchers)
        #self.assertEqual(len(self._add_dispatcher_messages), len(self._dispatchers))

if __name__ == "__main__":
    testutil.main()
