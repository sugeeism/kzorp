#ifndef _XT_SERVICE_H
#define _XT_SERVICE_H

enum {
	IPT_SERVICE_TYPE_ANY = 0,
	IPT_SERVICE_TYPE_PROXY,
	IPT_SERVICE_TYPE_FORWARD,
};

enum {
	IPT_SERVICE_NAME_ANY = 0,
	IPT_SERVICE_NAME_WILDCARD,
	IPT_SERVICE_NAME_MATCH,
};

#define IPT_SERVICE_NAME_LENGTH 117

struct ipt_service_info {
	u_int8_t type;
	u_int8_t name_match;
	unsigned char name[IPT_SERVICE_NAME_LENGTH + 1];

	unsigned int generation;
	unsigned int service_id;
};

#endif
