#ifndef _KZORP_INTERNAL_H
#define _KZORP_INTERNAL_H

/*
 * Contains some definitions common to all kzorp compilation unit.
 */

//         DIM_NAME        NL_ATTR_NAME TYPE                  NL_TYPE     LOOKUP_TYPE

#define KZORP_DIM_LIST(ACTION, _) \
  ACTION ( reqid,          REQID,       u_int32_t,            value,      u_int32_t            )_ \
  ACTION ( ifname,         IFACE,       ifname_t,             ifname,     ifname_t             )_ \
  ACTION ( ifgroup,        IFGROUP,     u_int32_t,            value,      u_int32_t            )_ \
  ACTION ( proto,          PROTO,       u_int8_t,             value,      u_int8_t             )_ \
  ACTION ( src_port,       SRC_PORT,    struct kz_port_range, portrange,  struct kz_port_range )_ \
  ACTION ( dst_port,       DST_PORT,    struct kz_port_range, portrange,  struct kz_port_range )_ \
  ACTION ( src_in_subnet,  SRC_IP,      struct kz_in_subnet,  in_subnet,  struct kz_in_subnet  )_ \
  ACTION ( src_in6_subnet, SRC_IP6,     struct kz_in6_subnet, in6_subnet, struct kz_in6_subnet )_ \
  ACTION ( src_zone,       SRC_ZONE,    struct kz_zone *,     string,     struct zone_lookup_t )_ \
  ACTION ( dst_in_subnet,  DST_IP,      struct kz_in_subnet,  in_subnet,  struct kz_in_subnet  )_ \
  ACTION ( dst_in6_subnet, DST_IP6,     struct kz_in6_subnet, in6_subnet, struct kz_in6_subnet )_ \
  ACTION ( dst_ifname,     DST_IFACE,   ifname_t,             ifname,     ifname_t             )_ \
  ACTION ( dst_ifgroup,    DST_IFGROUP, u_int32_t,            value,      u_int32_t            )_ \
  ACTION ( dst_zone,       DST_ZONE,    struct kz_zone *,     string,     struct zone_lookup_t )

#define KZORP_COMMA_SEPARATOR ,

#endif /* _KZORP_INTERNAL_H */
