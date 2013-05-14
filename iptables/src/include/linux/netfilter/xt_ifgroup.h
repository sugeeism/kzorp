#ifndef _XT_IFGROUP_H
#define _XT_IFGROUP_H

/* 
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
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
