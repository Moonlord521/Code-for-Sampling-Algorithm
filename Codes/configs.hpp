#ifndef CONFIGS_HPP
#define CONFIGS_HPP

#define CACHESIZE (32*1024)
#define CACHELINESIZE 64
#define CACHELINENUM (CACHESIZE/CACHELINESIZE)
#define WAY 4
#define WAYLINENUM (CACHELINENUM/WAY)

const unsigned int HASH_MAX = 65535;

const double W_FUNC = 1.0;
const double W_MISS = 1 - W_FUNC;

#define T_MISSRATE 0.05

#ifndef UNIT_SIZE
#define UNIT_SIZE 4000
#endif
#ifndef SECTION_SIZE
#define SECTION_SIZE 10
#endif

//const double T_DIST = 500;
#ifndef T_DIST_RATIO 
#define T_DIST_RATIO 0.04
#endif

#define T_DIST (UNIT_SIZE*T_DIST_RATIO)

#ifndef P_BASE
#define P_BASE 300000
#endif
#ifndef P_BASE2
#define P_BASE2 3
#endif

#endif
