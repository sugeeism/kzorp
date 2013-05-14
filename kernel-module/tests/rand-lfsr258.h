#ifndef MZ_RAND_LFSR258_H
#define MZ_RAND_LFSR258_H

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
/*

64 bit Combined Tausworth generator:

MATHEMATICS OF COMPUTATION
Volume 68, Number 225, January 1999, Pages 261-269
S 0025-5718(99)01039-X

TABLES OF MAXIMALLY EQUIDISTRIBUTED COMBINED LFSR GENERATORS
PIERRE L'ECUYER

*/

#define u64 unsigned long long

// The 1. / ((1<<64)-1) norm is decreased to be the 0 <= lfsr258(&seed) * LFSR258_NORM < 1.
#define LFSR258_NORM  5.4210108624275221e-20

typedef struct { u64 _1,_2,_3,_4,_5; } lfsr258_t;

extern u64 lfsr258(lfsr258_t *z);

typedef lfsr258_t kz_random_seed_t;

static inline unsigned kz_random_int(kz_random_seed_t *seed, u64 maximum)
{
  return (unsigned)((lfsr258(seed) * LFSR258_NORM) * (1. + maximum));
}

extern void kz_random_init(unsigned init_seed, kz_random_seed_t *seed);

#undef u64
#endif
