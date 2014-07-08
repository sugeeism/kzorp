#ifndef _XT_SERVICE_H
#define _XT_SERVICE_H

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
