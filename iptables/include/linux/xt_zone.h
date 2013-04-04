#ifndef _XT_ZONE_H
#define _XT_ZONE_H

/* flags */
enum {
	IPT_ZONE_SRC = 1,
	IPT_ZONE_CHILDREN = 2,
	IPT_ZONE_UMBRELLA = 4,
};

#define IPT_ZONE_NAME_LENGTH 126
#define IPT_ZONE_NAME_COUNT 32

struct ipt_zone_info {
	u_int8_t flags;
	unsigned char name[IPT_ZONE_NAME_LENGTH + 1];
};

struct ipt_zone_info_v1 {
	u_int8_t flags;
	u_int8_t count;
	unsigned char names[IPT_ZONE_NAME_COUNT][IPT_ZONE_NAME_LENGTH + 1];
};

#endif
