#include "test.h"
/*
 * Shared library add-on to iptables to match
 * packets by the incoming interface group.
 *
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

#define NUM_RULES 10000
#define NUM_INPUTS 5000
#define NUM_INTERFACES 50
#define NUM_ZONES 500
#define NUM_SUBNETS 500
#define NUM_SUBNETS6 250

// Per rule numbers:
#define MAX_INTERFACES (1 + num_interfaces / 20)
#define MAX_PORT_RANGE_COUNT 5
#define MAX_ZONE_COUNT (1 + num_zones / 50)
#define MAX_SUBNET_COUNT (1 + num_subnets / 100)
#define MAX_SUBNET6_COUNT (1 + num_subnets6 / 100)

#include "rand-lfsr258.h"
#include <linux/sort.h>
long long get_user_time();

int opt_dump = 0;
#define DUMP(FORMAT, PARAMS...) ((void)(opt_dump && printf(FORMAT, ##PARAMS)))

#define RAND_INT(MAX) \
({ \
  int rnd = kz_random_int(&seed, MAX); \
  DUMP("%d", rnd); \
  rnd; \
})

kz_random_seed_t seed;

int cmp_int_dec(const void *a, const void *b)
{
  return *(int *)b - *(int *)a;
}

int generate_port()
{
  return 1 + kz_random_int(&seed, 0xffff - 1);
}

void generate_port_ranges(struct kz_port_range *dst, int count)
{
  int points[2 * count];
  int i = 2 * count;
  while(i--) \
    points[i] = generate_port();
  sort(points, 2 * count, sizeof(int), cmp_int_dec, 0);
  for(i = 0; i < count; i++)
    {
      dst[i].from = points[2 * i];
      dst[i].to = points[2 * i + 1];
      DUMP("%s{%d, %d}", (i ? ", " : ""), dst[i].from, dst[i].to);
    }
}

void generate_interfaces(struct net_device *dst, int num_interfaces)
{
  memcpy(dst->name, "lo", sizeof("lo"));
  dst->group = 0;
  DUMP("interface[%d]: \"%s\", %d\n", 0, dst->name, dst->group);
  int i;
  for(i = 1; i < num_interfaces; i++)
    {
      snprintf(dst[i].name, sizeof(dst->name), "eth%d", i);
      dst[i].group = kz_random_int(&seed, 10);
      DUMP("interface[%d]: \"%s\", %d\n", i, dst[i].name, dst[i].group);
    }
}

void generate_zones(struct kz_zone *dst, int num_zones)
{
  int i;
  for(i = 0; i < num_zones; i++)
    {
      dst[i].index = kz_zone_index++;

      if(i > 5 && kz_random_int(&seed, 99) < 90)
        {
          dst[i].depth = (dst[i].admin_parent = &dst[1 + kz_random_int(&seed, i - 2)])->depth + 1;
        }
      else
        {
          dst[i].admin_parent = NULL;
          dst[i].depth = 0;
        }
      DUMP("zone[%d]:\n  depth: %d\n", i, dst[i].depth);
      if(dst[i].depth)
        DUMP("  admin_parent: %ld\n", dst[i].admin_parent - dst);
    }
}

struct kz_zone *zone;
int num_zones = 0;

int cmp_zone_dec(const void *a, const void *b)
{
  return zone[*(int *)b].depth - zone[*(int *)a].depth;
}

void generate_from_zones(struct kz_zone **dst, int count)
{
  int points[count];
  int i = count;
  while(i--)
    points[i] = kz_random_int(&seed, num_zones - 1);
  sort(points, count, sizeof(int), cmp_zone_dec, 0);
  i = count;
  while(i--)
    {
      dst[i] = &zone[points[i]];
      DUMP("%s%d", ((i < count - 1) ? ", " : ""), points[i]);
    }
}

char generate_protocols(u_int8_t **dst, u_int32_t *dst_count)
{
  struct { char proto; int rate; int hit; }
    protocol_distribution [] = {
      { IPPROTO_TCP, 45 }, { IPPROTO_UDP, 45 }, { IPPROTO_ICMP, 10 }, {}
    },
    *ptr;
  int count = dst ? kz_random_int(&seed, 3) : 1;
  while(count--)
    {
      int rnd = kz_random_int(&seed, 99);
      int rate = 0;
      for(ptr = protocol_distribution; ptr->rate; ++ptr)
        {
          rate += ptr->rate;
          if(rnd < rate)
            {
              if(!dst)
                {
                  DUMP((ptr->proto ==  IPPROTO_TCP) ? "TCP" : (ptr->proto ==  IPPROTO_UDP) ? "UDP" : "ICMP");
                  return ptr->proto;
                }
              ptr->hit = 1;
              break;
            }
        }
    }
  count = 0;
  for(ptr = protocol_distribution; ptr->rate; ++ptr)
    {
      if(ptr->hit)
        {
          (*dst = realloc(*dst, count + 1))[count] = ptr->proto;
          DUMP(count ? ", " : "");
          DUMP((ptr->proto ==  IPPROTO_TCP) ? "TCP" : (ptr->proto ==  IPPROTO_UDP) ? "UDP" : "ICMP");
          count++;
        }
    }
  *dst_count = count;
  return 0;
}

#define MAX_32_BIT_VALUE 0xffffffff

#define CMP_SUBNET_STUFF(VERSION) \
struct subnet##VERSION { int mask_size; struct kz_in##VERSION##_subnet addr; } *subnet##VERSION;\
int num_subnets##VERSION = 0;\
\
void generate_subnets##VERSION(struct subnet##VERSION *dst, int num_subnets)\
{\
  int address_length = (VERSION + 0) ? 4 : 1;\
  int have_zero_mask = 0;\
  while(num_subnets--)\
    {\
      int mask_size = kz_random_int(&seed, address_length * 32);\
      while(!(mask_size = kz_random_int(&seed, address_length * 32)) && (have_zero_mask || !(have_zero_mask = 1)));\
      __be32 address[4] = {};\
      __be32 mask[4] = {};\
      int i;\
      int bits;\
      DUMP("subnet" #VERSION "[%d]: 0x ", ({ static int i = 0; i++; }));\
      for(bits = mask_size, i = 0; bits > 0; bits-= 32, i++)\
        {\
          mask[i] = (bits >= 32) ? MAX_32_BIT_VALUE : MAX_32_BIT_VALUE ^ ((1 << (32 - bits))-1);\
          address[i] = kz_random_int(&seed, MAX_32_BIT_VALUE) & mask[i];\
          DUMP("%.8x ", address[i]);\
        }\
      DUMP("%s/ %d\n", mask_size ? "" : "0 ", mask_size);\
      dst->mask_size = mask_size;\
      memcpy(&dst->addr.addr, address, sizeof(address));\
      memcpy(&dst->addr.mask, address, sizeof(mask));\
      dst++;\
    }\
}\
\
int cmp_subnet##VERSION##_dec(const void *a, const void *b)\
{\
  return subnet##VERSION[*(int *)b].mask_size - subnet##VERSION[*(int *)a].mask_size;\
}\
\
void generate_from_subnets##VERSION(struct kz_in##VERSION##_subnet *dst, int count)\
{\
  int points[count];\
  int i = count;\
  while(i--)\
    points[i] = kz_random_int(&seed, num_subnets##VERSION - 1);\
  sort(points, count, sizeof(int), cmp_subnet##VERSION##_dec, 0);\
  i = count;\
  while(i--)\
    {\
      dst[i] = subnet##VERSION[points[i]].addr;\
      DUMP("%s%d", ((i < count - 1) ? ", " : ""), points[i]);\
    }\
}

CMP_SUBNET_STUFF()
CMP_SUBNET_STUFF(6)
#undef CMP_SUBNET_STUFF
#undef MAX_32_BIT_VALUE

struct net_device *interface;
int num_interfaces = 0;

void generate_rule(
  struct kz_dispatcher_n_dimension_rule *dst,
  int max_interface_count,
  int max_port_range_count,
  int max_zone_count,
  int max_subnet_count,
  int max_subnet6_count
)
{
#define GENERATE_RULE_ENTRY(NAME, MAX, GENERATOR, PARAMS...) \
({ \
  int count = kz_random_int(&seed, MAX); \
  DUMP("  "#NAME ": "); \
  dst->NAME = malloc(count * sizeof(*dst->NAME)); \
  dst->num_##NAME = count; \
  GENERATOR(dst->NAME, count, ##PARAMS); \
  DUMP("\n"); \
})

#define COPY_TO_ENTRY(ENTRY, COUNT, VALUE_REF) \
({ \
  int i = COUNT; \
  while(i--) \
    { \
      DUMP((i < COUNT - 1) ? ", " : ""); \
      memcpy(&ENTRY[i], &VALUE_REF, sizeof(*ENTRY)); \
    } \
})

#define OTHER_GENERATOR(_1, _2, _3) _3

  GENERATE_RULE_ENTRY(ifname, max_interface_count, COPY_TO_ENTRY, interface[RAND_INT(num_interfaces - 1)].name);
  GENERATE_RULE_ENTRY(ifgroup, max_interface_count, COPY_TO_ENTRY, interface[RAND_INT(num_interfaces - 1)].group);
  GENERATE_RULE_ENTRY(src_port, max_port_range_count, generate_port_ranges);
  GENERATE_RULE_ENTRY(dst_port, max_port_range_count, generate_port_ranges);
  GENERATE_RULE_ENTRY(src_zone, max_zone_count, generate_from_zones);
  GENERATE_RULE_ENTRY(dst_zone, max_zone_count, generate_from_zones);
  GENERATE_RULE_ENTRY(proto, 3, OTHER_GENERATOR, generate_protocols(&dst->proto, &dst->num_proto));
  GENERATE_RULE_ENTRY(src_in_subnet, max_subnet_count, generate_from_subnets);
  GENERATE_RULE_ENTRY(dst_in_subnet, max_subnet_count, generate_from_subnets);
  GENERATE_RULE_ENTRY(src_in6_subnet, max_subnet6_count, generate_from_subnets6);
  GENERATE_RULE_ENTRY(dst_in6_subnet, max_subnet6_count, generate_from_subnets6);
#undef GENERATE_RULE_ENTRY
#undef COPY_TO_ENTRY
#undef OTHER_GENERATOR
}

struct input {
  struct net_device iface;
  u_int8_t l3proto;
  union nf_inet_addr src_addr;
  union nf_inet_addr dst_addr;
  u_int8_t l4proto;
  u_int16_t src_port;
  u_int16_t dst_port;
  struct kz_zone src_zone;
  struct kz_zone dst_zone;
};

void generate_input(struct input *dst)
{
#define GENERATE_AF_DEP_FIELDS(VERSION) \
( \
  dst->l3proto = AF_INET##VERSION, \
  DUMP("  l3proto: IP" #VERSION), \
  DUMP("\n  src_addr: "), \
  dst->src_addr.in##VERSION = subnet##VERSION[RAND_INT(num_subnets##VERSION - 1)].addr.addr, \
  DUMP("\n  dst_addr: "), \
  dst->dst_addr.in##VERSION = subnet##VERSION[RAND_INT(num_subnets##VERSION - 1)].addr.addr \
)

  if(kz_random_int(&seed, 99) < 90)
    GENERATE_AF_DEP_FIELDS();
  else
    GENERATE_AF_DEP_FIELDS(6);
  DUMP("\n  iface: ");
  dst->iface = interface[RAND_INT(num_interfaces - 1)];
  DUMP("\n  l4proto: ");
  dst->l4proto = generate_protocols(0, 0);
  dst->src_port = generate_port();
  DUMP("\n  src_port: %d", dst->src_port);
  dst->dst_port = generate_port();
  DUMP("\n  dst_port: %d", dst->dst_port);
  DUMP("\n  src_zone: ");
  dst->src_zone = zone[RAND_INT(num_zones - 1)];
  DUMP("\n  dst_zone: ");
  dst->dst_zone = zone[RAND_INT(num_zones - 1)];
  DUMP("\n");
#undef GENERATE_AF_DEP_FIELDS
}

int main(int argc, char *argv[])
{

#define PARSE_OPTION(OPTION) \
  if(!strncmp(argv[argc], "--"#OPTION, sizeof("--"#OPTION) - 1)) \
    { \
      opt_##OPTION = argv[argc][sizeof("--"#OPTION) - 1] ? atoi(argv[argc] + sizeof("--"#OPTION)) : 1; \
      continue; \
    } \
  else

  while(argc-- > 0)
    {
      PARSE_OPTION(dump);
    }
#undef PARSE_OPTION

  kz_random_init(13, &seed);

  struct net_device _interface[NUM_INTERFACES] = {};
  interface = _interface;
  num_interfaces = NUM_INTERFACES;
  generate_interfaces(interface, num_interfaces);

  struct kz_zone _zone[NUM_ZONES] = {};
  zone = _zone;
  num_zones = NUM_ZONES;
  generate_zones(zone, num_zones);

  struct subnet _subnet[NUM_SUBNETS] = {};
  subnet = _subnet;
  num_subnets = NUM_SUBNETS;
  generate_subnets(subnet, num_subnets);

  struct subnet6 _subnet6[NUM_SUBNETS6] = {};
  subnet6 = _subnet6;
  num_subnets6 = NUM_SUBNETS6;
  generate_subnets6(subnet6, num_subnets6);

  struct kz_dispatcher_n_dimension_rule *rules = calloc(NUM_RULES, sizeof(*rules));
  {
    int count = NUM_RULES;
    while(count--)
      {
        DUMP("rule[%d]:\n", count);
        generate_rule(&rules[count], MAX_INTERFACES, MAX_PORT_RANGE_COUNT, MAX_ZONE_COUNT, MAX_SUBNET_COUNT, MAX_SUBNET6_COUNT);
      }
  }

  struct kz_dispatcher dispatcher = {
    .name = "test_dispatcher",
    .num_rule = NUM_RULES,
    .rule = rules
  };
  struct kz_head_d dispatchers = { .head = LIST_HEAD_INIT(dispatchers.head) };
  struct kz_percpu_env lenv = {
    .max_result_size = 2,
    .src_mask = calloc(1, KZ_ZONE_BF_SIZE),
    .dst_mask = calloc(1, KZ_ZONE_BF_SIZE),
    .result_rules = malloc(lenv.max_result_size * sizeof(*lenv.result_rules))
  };

  list_add(&dispatcher.list, &dispatchers.head);

  struct input *in = calloc(NUM_INPUTS, sizeof(*in));
  {
    int count = NUM_INPUTS;
    while(count--)
      {
        DUMP("input[%d]:\n", count);
        generate_input(&in[count]);
      }
  }

  kz_generate_lookup_data(&dispatchers);

  long long start_time = get_user_time();

  {
    struct input *i = in;
    printf("Number of matching rules:\n");
    for(; i < in + NUM_INPUTS; ++i)
      {
        printf("%d ",
          kz_ndim_eval(
            0,
            &i->iface,
            i->l3proto,
            &i->src_addr,
            &i->dst_addr,
            i->l4proto,
            i->src_port,
            i->dst_port,
            &i->src_zone,
            &i->dst_zone,
            &dispatchers,
            &lenv
          )
        );
      }
    long long time_elapsed = get_user_time() - start_time;
    printf("\nuser time: %lld us\n", time_elapsed);
    printf("%lld lookup/s\n", NUM_INPUTS * 1000000ll / time_elapsed);
  }
  return 0;
}
