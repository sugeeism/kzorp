#ifndef _XT_IFGROUP_H
#define _XT_IFGROUP_H

#define XT_IFGROUP_INVERT_IN	0x01
#define XT_IFGROUP_INVERT_OUT	0x02
#define XT_IFGROUP_MATCH_IN	0x04
#define XT_IFGROUP_MATCH_OUT	0x08

struct xt_ifgroup_info {
	u_int32_t in_group;
	u_int32_t in_mask;
	u_int32_t out_group;
	u_int32_t out_mask;
	u_int8_t flags;
};

#endif /*_XT_IFGROUP_H*/
