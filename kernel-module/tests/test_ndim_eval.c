
/*
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "test.h"

struct kz_rule_lookup_cursor *
set_cursor(struct kz_rule_lookup_data *rule_data) {
  static struct kz_rule_lookup_cursor cursor;
  cursor.rule = rule_data;
  cursor.pos = sizeof(struct kz_rule_lookup_data);
  return &cursor;
}

void test_eval_port()
{
  const struct kz_dispatcher_n_dimension_rule rules[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(src_port, { 10, 10 }, {60000, 65535 }) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_port, { 10, 10 }, {60000, 65535 }) }
  };

#define EVAL_PORT(RULE_DATA, PORT) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, NULL, NULL, 0, NULL, NULL, 0, PORT, PORT, NULL, NULL, NULL, NULL)

  struct kz_rule_lookup_data *empty_rule_data = kz_generate_lookup_data_rule(&rules[0], malloc(kz_generate_lookup_data_rule_size(&rules[0])));
  struct kz_rule_lookup_data *rule_data = kz_generate_lookup_data_rule(&rules[1], malloc(kz_generate_lookup_data_rule_size(&rules[1])));

  // Test when no matching port range was found:
  g_assert(EVAL_PORT(rule_data, 22) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_PORT(rule_data, 59999) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_PORT(rule_data, 9) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_PORT(rule_data, 11) == KZ_NOT_MATCHING_SCORE);

  // Test when a matching range of size larger than one was found:
  u_int64_t score_of_matching_range_with_size_from_2 = EVAL_PORT(rule_data, 60000);
  g_assert(EVAL_PORT(rule_data, 65535) == score_of_matching_range_with_size_from_2);
  g_assert(EVAL_PORT(rule_data, 62000) == score_of_matching_range_with_size_from_2);

  // Test if empty port range matches:
  g_assert(EVAL_PORT(empty_rule_data, 22) < score_of_matching_range_with_size_from_2);

  // Test when a matching range of size one was found:
  g_assert(score_of_matching_range_with_size_from_2 < EVAL_PORT(rule_data, 10));
#undef EVAL_PORT
}

#include <linux/inetdevice.h>

void test_dim_precedency()
{
  struct kz_zone zone = KZ_ZONE_ROOT_INITIALIZER;
  unsigned long zone_mask = 1 << zone.index;

  const union nf_inet_addr address = { .all = { 0x12345678 } };

  struct in_ifaddr in_ifaddr = { .ifa_local = address.all[0] };
  struct in_device in_device = { .ifa_list = &in_ifaddr };
  const struct net_device iface = { .name = "eth0", .group = 9, .ip_ptr = &in_device };

  const u_int16_t port = 12345;

  const u_int8_t l4proto = IPPROTO_UDP;

  const struct kz_reqids reqids = { .len = 1, .vec = { } };

#define RULE_INITIALIZER(SET_1, SET_2, SET_3, SET_4, SET_5, SET_6, SET_7, SET_8, SET_9, SET_10, SET_11, SET_12) \
  { \
    SET_1(KZ_RULE_ENTRY_INITIALIZER(dst_zone, &zone)) \
    SET_2(KZ_RULE_ENTRY_INITIALIZER(dst_ifgroup, iface.group)) \
    SET_3(KZ_RULE_ENTRY_INITIALIZER(dst_ifname, "eth0")) \
    SET_4(KZ_RULE_ENTRY_INITIALIZER(dst_in_subnet, { {}, {} })) \
    SET_5(KZ_RULE_ENTRY_INITIALIZER(src_zone, &zone)) \
    SET_6(KZ_RULE_ENTRY_INITIALIZER(src_in_subnet, { {}, {} })) \
    SET_7(KZ_RULE_ENTRY_INITIALIZER(dst_port, { port, port })) \
    SET_8(KZ_RULE_ENTRY_INITIALIZER(src_port, { port, port })) \
    SET_9(KZ_RULE_ENTRY_INITIALIZER(proto, l4proto)) \
    SET_10(KZ_RULE_ENTRY_INITIALIZER(ifgroup, iface.group)) \
    SET_11(KZ_RULE_ENTRY_INITIALIZER(ifname, "eth0")) \
    SET_12(KZ_RULE_ENTRY_INITIALIZER(reqid, 0)) \
  }

#define SET_LAST(ENTRY) ENTRY
#define SET(ENTRY) ENTRY,
#define OFF(ENTRY)

  const struct kz_dispatcher_n_dimension_rule rules[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(dst_zone, &zone) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifgroup, iface.group) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifname, "eth0") },
    { KZ_RULE_ENTRY_INITIALIZER(dst_in_subnet, { {}, {} }) },
    { KZ_RULE_ENTRY_INITIALIZER(src_zone, &zone) },
    { KZ_RULE_ENTRY_INITIALIZER(src_in_subnet, { {}, {} }) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_port, { port, port }) },
    { KZ_RULE_ENTRY_INITIALIZER(src_port, { port, port }) },
    { KZ_RULE_ENTRY_INITIALIZER(proto, l4proto) },
    { KZ_RULE_ENTRY_INITIALIZER(ifgroup, iface.group) },
    { KZ_RULE_ENTRY_INITIALIZER(ifname, "eth0") },
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET_LAST, OFF),
    { KZ_RULE_ENTRY_INITIALIZER(reqid, 0) },
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, SET, SET, SET, OFF, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, SET, SET, OFF, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, SET, OFF, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, OFF, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, OFF, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, OFF, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, OFF, SET, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, OFF, SET, SET, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, OFF, SET, SET, SET, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, OFF, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(OFF, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET_LAST),
    RULE_INITIALIZER(SET, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET, SET_LAST)
  };

#undef OFF
#undef SET
#undef SET_LAST
#undef RULE_INITIALIZER

  struct kz_rule_lookup_data* rule_data_arr[sizeof(rules)/sizeof(*rules)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

#define EVAL_RULE(ARGS...) \
  kz_ndim_eval_rule(set_cursor(rule_data_arr[i++]), 0, ARGS)

#define EVAL_RULE_WITH_COMPLETE_INPUT \
  EVAL_RULE(&reqids, &iface, AF_INET, &address, &address, l4proto, port, port, &zone, &zone, &zone_mask, &zone_mask)

  i = 0;

  u_int64_t scores[] = {
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, 0, 0, 0, NULL, &zone, NULL, &zone_mask),
    EVAL_RULE(NULL, &iface, AF_INET, NULL, &address, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, &iface, AF_INET, NULL, &address, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, AF_INET, NULL, &address, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, 0, 0, 0, &zone, NULL, &zone_mask, NULL),
    EVAL_RULE(NULL, NULL, AF_INET, &address, NULL, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, 0, 0, port, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, 0, port, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, NULL, 0, NULL, NULL, l4proto, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, &iface, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE(NULL, &iface, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE(&reqids, &iface, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL),
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT,
    EVAL_RULE_WITH_COMPLETE_INPUT
  };

#undef EVAL_RULE_WITH_COMPLETE_INPUT
#undef EVAL_RULE

  u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
  while(--score > scores) {
    g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
    g_assert(score[-1] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
  }
}

void test_eval_dst_ifgroup()
{
  const union nf_inet_addr address[] = {
    { .all = { 0x12345678 } },
    { .all = { 0x9abcdef1 } }
  };

  u_int32_t
    group1 = 0xaaa555a5,
    group2 = 0x555a55af;

  struct in_ifaddr in_ifaddr = { .ifa_local = address[0].all[0] };
  struct in_device in_device = { .ifa_list = &in_ifaddr };
  const struct net_device iface = { .group = group1, .ip_ptr = &in_device };

  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifgroup, iface.group) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifgroup, group2) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifgroup, group2, group1) }
  };

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE_DATA, ADDRESS) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, NULL, &iface, AF_INET, NULL, &ADDRESS, 0, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], address[1]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], address[0]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], address[1]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[3], address[1]) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], address[0]);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[3], address[0]) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], address[1]) < matching_score);

#undef EVAL_RULE
}

void test_eval_dst_ifname()
{
  const union nf_inet_addr address[] = {
    { .all = { 0x12345678 } },
    { .all = { 0x9abcdef1 } }
  };

#define NAME1 "eth0"
#define NAME2 "eth1"
#define NAME3 "tun0"

  struct in_ifaddr in_ifaddr = { .ifa_local = address[0].all[0] };
  struct in_device in_device = { .ifa_list = &in_ifaddr };
  const struct net_device iface = { .name = NAME1, .ip_ptr = &in_device };

  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifname, NAME1) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifname, NAME2) },
    { KZ_RULE_ENTRY_INITIALIZER(dst_ifname, NAME3, NAME1) }
  };

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE, ADDRESS) \
  kz_ndim_eval_rule(set_cursor(RULE), 0, NULL, &iface, AF_INET, NULL, &ADDRESS, 0, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], address[1]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], address[0]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], address[1]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[3], address[1]) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], address[0]);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[3], address[0]) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], address[1]) < matching_score);

#undef NAME1
#undef NAME2
#undef NAME3
#undef EVAL_RULE
}

#define MASK(NUM_BITS) \
  htonl( (NUM_BITS < 32) ? (NUM_BITS > 0) ? (0xffffffff << (32 - NUM_BITS)) & 0xffffffff : 0 : 0xffffffff )

#define MASK6(NUM_BITS) \
  .s6_addr32 = { MASK(NUM_BITS), MASK(NUM_BITS - 0x20), MASK(NUM_BITS - 0x40), MASK(NUM_BITS - 0x60) }

void test_mask_to_size_v4()
{
  unsigned num_bits;
  for(num_bits = 0; num_bits <= 32; num_bits++) {
    struct in_addr mask = { MASK(num_bits) };
    g_assert_cmpuint(mask_to_size_v4(&mask), ==, num_bits);
  }
}

void test_mask_to_size_v6()
{
  unsigned num_bits;
  for(num_bits = 0; num_bits <= 128; num_bits++) {
    struct in6_addr mask = { MASK6(num_bits) };
    g_assert_cmpuint(mask_to_size_v6(&mask), ==, num_bits);
  }
}

void test_eval_subnet()
{
  const union nf_inet_addr mask[] = {
    { .all = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff } },
    { .all = { 0xffffffff, htonl(0xfff80000) } },
    { .all = { htonl(0xfffc0000) } },
    { .all = { htonl(0xfff80000) } },
    { .all = { 0xffffffff, htonl(0xfffc0000) } }
  };
  const union nf_inet_addr address[] = {
    { .all = { htonl(0x12385678), htonl(0x9abcdef1), 0x23456789, 0xabcdef12 } },
    { .all = { htonl(0x12380000) } },
    { .all = { htonl(0xa555aa5a) } },
    { .all = { htonl(0x12385678), htonl(0x9ab80000) } },
  };

#define EVAL_RULE(VER, ADDRESS) \
  kz_ndim_eval_rule(set_cursor(rule_data_arr[i++]), 0, NULL, NULL, AF_INET##VER, NULL, &ADDRESS, 0, 0, 0, NULL, NULL, NULL, NULL), \
  kz_ndim_eval_rule(set_cursor(rule_data_arr[i++]), 0, NULL, NULL, AF_INET##VER, &ADDRESS, NULL, 0, 0, 0, NULL, NULL, NULL, NULL)

#define DEF_RULE(VER, ELEMENTS...) \
  { KZ_RULE_ENTRY_INITIALIZER(dst_in##VER##_subnet, ELEMENTS) }, \
  { KZ_RULE_ENTRY_INITIALIZER(src_in##VER##_subnet, ELEMENTS) }

  // Test not matching:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(, { address[2].in, mask[0].in }),
      DEF_RULE(6, { address[0].in6, mask[0].in6 }),
      DEF_RULE(, { address[1].in, mask[0].in  }),
      DEF_RULE(6, { address[3].in6, mask[0].in6 }),
      DEF_RULE(6, { address[0].in6, mask[0].in6 }),
      DEF_RULE(, { address[0].in, mask[0].in })
    };
    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      // different addresses:
      EVAL_RULE(, address[0]),
      EVAL_RULE(6, address[2]),
      // would match with shorter mask:
      EVAL_RULE(, address[0]),
      EVAL_RULE(6, address[0]),
      // different protocols:
      EVAL_RULE(, address[0]),
      EVAL_RULE(6, address[0])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores) {
      g_assert(*score == KZ_NOT_MATCHING_SCORE || (printf("Should not match rules[%ld].\n", score - scores), 0));
    }
  }

  // Test matching of increasing mask size of IPV4:
  {
    int num_bits;
    u_int64_t score_less[2] = {};
    const union nf_inet_addr address = {};

    for(num_bits = 0; num_bits <= 32; num_bits++) {
      const struct kz_dispatcher_n_dimension_rule rules[] = {
        DEF_RULE(, { {}, { MASK(num_bits) } })
      };

      struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
      int i;
      for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
        rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

      i = 0;

      u_int64_t scores[] = {
        score_less[0], score_less[1],
        EVAL_RULE(, address)
      };

      u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
      while(--score > scores + 1) {
        g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
        g_assert(score[-2] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
        score_less[(score - scores) % 2] = *score;
      }
    }
  }

  // Test matching of increasing mask size of IPV6:
  {
    int num_bits;
    u_int64_t score_less[2] = {};
    const union nf_inet_addr address = {};

    for(num_bits = 0; num_bits <= 128; num_bits++) {
      const struct kz_dispatcher_n_dimension_rule rules[] = {
        DEF_RULE(6, { {}, { MASK6(num_bits) } })
      };

      struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
      int i;
      for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
        rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

      i = 0;

      u_int64_t scores[] = {
        score_less[0], score_less[1],
        EVAL_RULE(6, address)
      };

      u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
      while(--score > scores + 1) {
        g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
        g_assert(score[-2] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
        score_less[(score - scores) % 2] = *score;
      }
    }
  }

  // Test matching of different addresses and increasing mask size:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      {}, {},
      DEF_RULE(, { address[1].in, mask[3].in }),
      DEF_RULE(, { address[1].in, mask[2].in }),
      DEF_RULE(, { address[0].in, mask[0].in }),
      DEF_RULE(6, { address[3].in6, mask[1].in6 }),
      DEF_RULE(6, { address[3].in6, mask[4].in6 }),
      DEF_RULE(6, { address[0].in6, mask[0].in6 })
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      EVAL_RULE(, address[0]),
      EVAL_RULE(, address[0]),
      EVAL_RULE(, address[0]),
      EVAL_RULE(, address[0]),
      EVAL_RULE(6, address[0]),
      EVAL_RULE(6, address[3]),
      EVAL_RULE(6, address[0])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
    }
  }

  // Test matching different addresses with the same score and mask size < 32:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(, { address[1].in, mask[3].in }),
      DEF_RULE(, { address[1].in, mask[3].in }),
      DEF_RULE(, { address[0].in, mask[0].in }, { address[1].in, mask[3].in }),
      DEF_RULE(6, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[3].in6, mask[1].in6 }, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[0].in6, mask[0].in6 }, { address[3].in6, mask[1].in6 }, { address[1].in6, mask[3].in6 })
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      EVAL_RULE(, address[0]),
      EVAL_RULE(, address[1]),
      EVAL_RULE(, address[1]),
      EVAL_RULE(6, address[0]),
      EVAL_RULE(6, address[1]),
      EVAL_RULE(6, address[3]),
      EVAL_RULE(6, address[1]),
      EVAL_RULE(6, address[1])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] == *score || (printf("Score of rules[%ld] should be the same.\n", score - scores), 0));
    }
  }

  // Test matching different addresses with the same score and mask size > 32:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(6, { address[3].in6, mask[1].in6 }),
      DEF_RULE(6, { address[3].in6, mask[1].in6 }),
      DEF_RULE(6, { address[3].in6, mask[1].in6 }, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[3].in6, mask[1].in6 }, { address[1].in6, mask[3].in6 }),
      DEF_RULE(6, { address[0].in6, mask[0].in6 }, { address[3].in6, mask[1].in6 }, { address[1].in6, mask[3].in6 })
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      EVAL_RULE(6, address[0]),
      EVAL_RULE(6, address[3]),
      EVAL_RULE(6, address[0]),
      EVAL_RULE(6, address[3]),
      EVAL_RULE(6, address[3])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] == *score || (printf("Score of rules[%ld] should be the same.\n", score - scores), 0));
    }
  }
#undef DEF_RULE
#undef EVAL_RULE
}

#undef MASK6
#undef MASK

void test_mark_zone_path()
{
  kz_zone_index = 0;

  struct kz_zone zone[] = {
    KZ_ZONE_ROOT_INITIALIZER,
    KZ_ZONE_INITIALIZER(zone[0]),
    KZ_ZONE_INITIALIZER(zone[1])
  };

  unsigned long zone_mask_ref = 0;
  int i;
  for(i = 0; i < sizeof(zone) / sizeof(*zone); i++) {
    unsigned long zone_mask = 0;
    zone_mask_ref |= 1 << zone[i].index;
    mark_zone_path(&zone_mask, &zone[i]);
    g_assert(zone_mask == zone_mask_ref);
  }
}

void test_eval_zone()
{
  kz_zone_index = 0;

  struct kz_zone zone[] = {
    KZ_ZONE_ROOT_INITIALIZER,
    KZ_ZONE_INITIALIZER(zone[0]),
    KZ_ZONE_INITIALIZER(zone[1]),
    KZ_ZONE_ROOT_INITIALIZER,
    KZ_ZONE_INITIALIZER(zone[3])
  };

#define DEF_RULE(ZONE_ADDRESSES...) \
  { KZ_RULE_ENTRY_INITIALIZER(dst_zone, ZONE_ADDRESSES) }, \
  { KZ_RULE_ENTRY_INITIALIZER(src_zone, ZONE_ADDRESSES) }

  unsigned long zone_mask = 0;

#define EVAL_ZONE(ZONE) \
  ( \
    zone_mask = 0, mark_zone_path(&zone_mask, &ZONE), \
    kz_ndim_eval_rule(set_cursor(rule_data_arr[i++]), 0, NULL, NULL, 0, NULL, NULL, 0, 0, 0, NULL, &ZONE, NULL, &zone_mask) \
  ), \
  kz_ndim_eval_rule(set_cursor(rule_data_arr[i++]), 0, NULL, NULL, 0, NULL, NULL, 0, 0, 0, &ZONE, NULL, &zone_mask, NULL)

  // Test not matching:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(&zone[0]),
      DEF_RULE(&zone[2])
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      EVAL_ZONE(zone[3]),
      EVAL_ZONE(zone[1])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores) {
      g_assert(*score == KZ_NOT_MATCHING_SCORE || (printf("Should not match rules[%ld].\n", score - scores), 0));
    }
  }
  // Test zones in one hierarchy:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      {}, {},
      DEF_RULE(&zone[0]),
      DEF_RULE(&zone[1]),
      DEF_RULE(&zone[2])
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));

    i = 0;

    u_int64_t scores[] = {
      EVAL_ZONE(zone[2]),
      EVAL_ZONE(zone[2]),
      EVAL_ZONE(zone[2]),
      EVAL_ZONE(zone[2])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
    }
  }
  // Test equal score cases in the same and different hierarchies:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(&zone[1]),
      DEF_RULE(&zone[1]),
      DEF_RULE(&zone[4]),
      DEF_RULE(&zone[4], &zone[1])
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));
    i = 0;

    u_int64_t scores[] = {
      EVAL_ZONE(zone[1]),
      EVAL_ZONE(zone[2]),
      EVAL_ZONE(zone[4]),
      EVAL_ZONE(zone[1])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] == *score || (printf("Score of rules[%ld] should be the same.\n", score - scores), 0));
    }
  }
  // Test finding the most specific zone:
  {
    const struct kz_dispatcher_n_dimension_rule rules[] = {
      DEF_RULE(&zone[2], &zone[1], &zone[0], &zone[3]),
      DEF_RULE(&zone[2], &zone[1], &zone[0]),
      DEF_RULE(&zone[2], &zone[1], &zone[0])
    };

    struct kz_rule_lookup_data *rule_data_arr[sizeof(rules)/sizeof(*rules)];
    int i;
    for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
      rule_data_arr[i] = kz_generate_lookup_data_rule(&rules[i], malloc(kz_generate_lookup_data_rule_size(&rules[i])));
    i = 0;

    u_int64_t scores[] = {
      EVAL_ZONE(zone[3]),
      EVAL_ZONE(zone[1]),
      EVAL_ZONE(zone[2])
    };

    u_int64_t *score = scores + sizeof(scores) / sizeof(*scores);
    while(--score > scores + 1) {
      g_assert(*score != KZ_NOT_MATCHING_SCORE || (printf("Does not match rules[%ld].\n", score - scores), 0));
      g_assert(score[-2] < *score || (printf("Score of rules[%ld] is not greater.\n", score - scores), 0));
    }
  }
#undef DEF_RULE
#undef EVAL_ZONE
}

void test_eval_proto()
{
  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(proto, IPPROTO_UDP) },
    { KZ_RULE_ENTRY_INITIALIZER(proto, IPPROTO_UDP, IPPROTO_TCP) }
  };

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE_DATA, PROTOCOL) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, NULL, NULL, 0, NULL, NULL, PROTOCOL, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], IPPROTO_TCP) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], IPPROTO_ICMP) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], IPPROTO_UDP);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], IPPROTO_TCP) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[2], IPPROTO_UDP) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], IPPROTO_ICMP) < matching_score);

#undef EVAL_RULE
}

void test_eval_ifgroup()
{
  const struct net_device iface[] = {
    { .group = 0x5a },
    { .group = 0xa5 },
    { .group = 0xfa }
  };

  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(ifgroup, iface[1].group) },
    { KZ_RULE_ENTRY_INITIALIZER(ifgroup, iface[0].group, iface[1].group) }
  };

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE_DATA, IFACE) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, NULL, &IFACE, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], iface[0]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[2]) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], iface[1]);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[0]) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[1]) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], iface[2]) < matching_score);

#undef EVAL_RULE
}

void test_eval_ifname()
{
  const struct net_device iface[] = {
    { .name = "lo" },
    { .name = "eth0" },
    { .name = "eth1" }
  };

  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(ifname, "eth1") },
    { KZ_RULE_ENTRY_INITIALIZER(ifname, "eth0", "eth1") }
  };

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE_DATA, IFACE) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, NULL, &IFACE, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], iface[1]) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[0]) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], iface[2]);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[1]) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[2], iface[2]) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], iface[0]) < matching_score);

#undef EVAL_RULE
}

void test_eval_reqid()
{
  struct kz_reqids kz_reqids1 = { .len = 1, .vec = { } };
  struct kz_reqids kz_reqids2 = {
    .len = 2,
    .vec = { }
  };

  u_int32_t
    reqid1 = 0xf5fa55af,
    reqid2 = 0x5aa5ffaa,
    reqid3 = 0xaa55fa5a,
    reqid4 = 0xa55a5aa5;

  kz_reqids1.vec[0] = reqid1;
  kz_reqids2.vec[0] = reqid2;
  kz_reqids2.vec[1] = reqid3;

  const struct kz_dispatcher_n_dimension_rule rule[] = {
    {},
    { KZ_RULE_ENTRY_INITIALIZER(reqid, reqid3) },
    { KZ_RULE_ENTRY_INITIALIZER(reqid, reqid4, reqid1) },
    { KZ_RULE_ENTRY_INITIALIZER(reqid, reqid1, reqid2) },
    { KZ_RULE_ENTRY_INITIALIZER(reqid, reqid3, reqid2) }
  };

  const struct net_device iface = {};

  struct kz_rule_lookup_data *rule_data_arr[sizeof(rule)/sizeof(*rule)];
  int i;
  for (i = 0; i < sizeof(rule_data_arr)/sizeof(*rule_data_arr); ++i)
    rule_data_arr[i] = kz_generate_lookup_data_rule(&rule[i], malloc(kz_generate_lookup_data_rule_size(&rule[i])));

#define EVAL_RULE(RULE_DATA, SEC_PATH) \
  kz_ndim_eval_rule(set_cursor(RULE_DATA), 0, &SEC_PATH, &iface, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL)

  // Test not matching:
  g_assert(EVAL_RULE(rule_data_arr[1], kz_reqids1) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], kz_reqids2) == KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[4], kz_reqids1) == KZ_NOT_MATCHING_SCORE);

  // Test matching:
  u_int64_t matching_score = EVAL_RULE(rule_data_arr[1], kz_reqids2);
  g_assert(matching_score != KZ_NOT_MATCHING_SCORE);
  g_assert(EVAL_RULE(rule_data_arr[2], kz_reqids1) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[3], kz_reqids1) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[3], kz_reqids2) == matching_score);
  g_assert(EVAL_RULE(rule_data_arr[4], kz_reqids2) == matching_score);

  // Test empty rule matches and scores less:
  g_assert(EVAL_RULE(rule_data_arr[0], kz_reqids2) < matching_score);

#undef EVAL_RULE
}

void test_result_of_ndim_eval()
{
  struct kz_head_d dispatchers = { .head = LIST_HEAD_INIT(dispatchers.head) };
  struct kz_percpu_env lenv = {
    .max_result_size = 2,
    .src_mask = calloc(1, KZ_ZONE_BF_SIZE),
    .dst_mask = calloc(1, KZ_ZONE_BF_SIZE),
    .result_rules = malloc(lenv.max_result_size * sizeof(*lenv.result_rules))
  };

  struct kz_dispatcher_n_dimension_rule rule1[] = {
    { KZ_RULE_ENTRY_INITIALIZER(proto, IPPROTO_UDP, IPPROTO_ICMP) }
  };

  struct kz_dispatcher_n_dimension_rule rule2[] = {
    { KZ_RULE_ENTRY_INITIALIZER(proto, IPPROTO_ICMP) },
    { KZ_RULE_ENTRY_INITIALIZER(proto, IPPROTO_TCP) }
  };

  struct kz_dispatcher dispatcher[] = {
    { .num_rule = 1, .rule = rule1 },
    { .num_rule = 2, .rule = rule2 }
  };

  rule1[0].dispatcher = &dispatcher[0];
  rule2[0].dispatcher = rule2[1].dispatcher = &dispatcher[1];

  list_add(&dispatcher[0].list, &dispatchers.head);
  list_add(&dispatcher[1].list, &dispatchers.head);

  kz_generate_lookup_data(&dispatchers);

  // Test when numbers of results are one:
  lenv.result_rules[0] = NULL;
  g_assert(kz_ndim_eval(NULL, NULL, 0, NULL, NULL, IPPROTO_UDP, 0, 0, NULL, NULL, &dispatchers, &lenv) == 1);
  g_assert(lenv.result_rules[0] == &rule1[0]);

  lenv.result_rules[0] = NULL;
  g_assert(kz_ndim_eval(NULL, NULL, 0, NULL, NULL, IPPROTO_TCP, 0, 0, NULL, NULL, &dispatchers, &lenv) == 1);
  g_assert(lenv.result_rules[0] == &rule2[1]);

  // Test when number of results is two:
  lenv.result_rules[0] = lenv.result_rules[1] = NULL;
  g_assert(kz_ndim_eval(NULL, NULL, 0, NULL, NULL, IPPROTO_ICMP, 0, 0, NULL, NULL, &dispatchers, &lenv) == 2);
  g_assert(lenv.result_rules[0] == &rule1[0] || lenv.result_rules[0] == &rule2[0]);
  if(lenv.result_rules[0] == &rule1[0])
    {
      g_assert(lenv.result_rules[1] == &rule2[0]);
    }
  else
    {
      g_assert(lenv.result_rules[1] == &rule1[0]);
    }
}

int main(int argc, char *argv[])
{
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/kzorp/result_of_ndim_eval", test_result_of_ndim_eval);
  g_test_add_func("/kzorp/eval_dst_ifgroup", test_eval_dst_ifgroup);
  g_test_add_func("/kzorp/eval_dst_ifname", test_eval_dst_ifname);
  g_test_add_func("/kzorp/mask_to_size_v4", test_mask_to_size_v4);
  g_test_add_func("/kzorp/mask_to_size_v6", test_mask_to_size_v6);
  g_test_add_func("/kzorp/eval_subnet", test_eval_subnet);
  g_test_add_func("/kzorp/mark_zone_path", test_mark_zone_path);
  g_test_add_func("/kzorp/eval_zone", test_eval_zone);
  g_test_add_func("/kzorp/eval_port", test_eval_port);
  g_test_add_func("/kzorp/eval_proto", test_eval_proto);
  g_test_add_func("/kzorp/eval_ifgroup", test_eval_ifgroup);
  g_test_add_func("/kzorp/eval_ifname", test_eval_ifname);
  g_test_add_func("/kzorp/eval_reqid", test_eval_reqid);
  g_test_add_func("/kzorp/dim_precedency", test_dim_precedency);

  g_test_run();

  return 0;
}
