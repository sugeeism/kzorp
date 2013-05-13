/*
MATHEMATICS OF COMPUTATION
Volume 68, Number 225, January 1999, Pages 261-269
S 0025-5718(99)01039-X

TABLES OF MAXIMALLY EQUIDISTRIBUTED COMBINED LFSR GENERATORS
PIERRE L'ECUYER

unsigned long long z1, z2, z3, z4, z5;
double lfsr258 ()
{ // Generates numbers between 0 and 1. //
unsigned long long b;
b = (((z1 << 1) ^ z1) >> 53);
z1 = (((z1 & 18446744073709551614) << 10) ^ b);
b = (((z2 << 24) ^ z2) >> 50);
z2 = (((z2 & 18446744073709551104) << 5) ^ b);
b = (((z3 << 3) ^ z3) >> 23);
z3 = (((z3 & 18446744073709547520) << 29) ^ b);
b = (((z4 << 5) ^ z4) >> 24);
z4 = (((z4 & 18446744073709420544) << 23) ^ b);
b = (((z5 << 3) ^ z5) >> 33);
z5 = (((z5 & 18446744073701163008) << 8) ^ b);
return ((z1 ^ z2 ^ z3 ^ z4 ^ z5) * 5.4210108624275221e-20);
}
*/

#include "rand-lfsr258.h"

#define u64 unsigned long long

#define M1 18446744073709551614ull
#define M2 18446744073709551104ull
#define M3 18446744073709547520ull
#define M4 18446744073709420544ull
#define M5 18446744073701163008ull

#define TAUSW(S,M,_1,_2,_3) ( ((S & M) << _1) ^ (((S << _2) ^ S) >> _3) )

u64 lfsr258(lfsr258_t *z)
{
 z->_1= TAUSW(z->_1,M1,  10,  1, 53);
 z->_2= TAUSW(z->_2,M2,   5, 24, 50);
 z->_3= TAUSW(z->_3,M3,  29,  3, 23);
 z->_4= TAUSW(z->_4,M4,  23,  5, 24);
 z->_5= TAUSW(z->_5,M5,   8,  3, 33);
 return (z->_1 ^ z->_2 ^ z->_3 ^ z->_4 ^ z->_5);
}

/*
D. E. Knuth. The Art of Computer Programming,
Volume 2: Seminumerical Algorithms, Third Edition. Addison-Wesley, 1997.
ISBN 0-201-89684-2. Section 3.2.1: The Linear Congruential Method, pp. 10–26.
*/
#define LCG(x) (6364136223846793005ull * (u64)(x) + 1442695040888963407ull)

void kz_random_init(unsigned seed,lfsr258_t *z)
{
 z->_1= LCG(seed?seed:1);
 z->_2= LCG(z->_1);
 z->_3= LCG(z->_2);
 z->_4= LCG(z->_3);
 z->_5= LCG(z->_4);
#define INIT_MIN(n) if(!(z->_##n & M##n)) z->_##n|= 1+~M##n
 INIT_MIN(1);
 INIT_MIN(2);
 INIT_MIN(3);
 INIT_MIN(4);
 INIT_MIN(5);
}
