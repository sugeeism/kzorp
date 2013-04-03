#ifndef MZ_RAND_LFSR258_H
#define MZ_RAND_LFSR258_H

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
