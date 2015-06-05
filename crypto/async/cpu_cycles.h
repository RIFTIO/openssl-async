
#define QAT_CPU_CYCLES_COUNT

#ifdef QAT_CPU_CYCLES_COUNT

typedef unsigned long long cpucycle_t;

// This implementation is from speed
static __inline__ unsigned long long rdtsc(void)
{
    unsigned long a, d;

    asm volatile ("rdtsc":"=a" (a), "=d"(d));
    return (((unsigned long long)a) | (((unsigned long long)d) << 32));
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

// For every operation I keep track of an accumulator + counter
cpucycle_t fibre_startup_acc = 0;
unsigned int fibre_startup_num = 0;

cpucycle_t fibre_switch_acc = 0;
unsigned int fibre_switch_num = 0;

cpucycle_t fibre_destroy_acc = 0;
unsigned int fibre_destroy_num = 0;

#define QAT_FIBRE_STARTUP_SAMPLE 1000
#define QAT_FIBRE_SWITCH_SAMPLE 1000
#define QAT_FIBRE_DESTROY_SAMPLE 1000

// TODO are we interested in these?
// I think they are useful to detect anomalies
cpucycle_t fibre_startup_min = 999999;
cpucycle_t fibre_startup_max = 0;

cpucycle_t fibre_switch_min = 999999;
cpucycle_t fibre_switch_max = 0;

cpucycle_t fibre_destroy_min = 999999;
cpucycle_t fibre_destroy_max = 0;

// I also need to remember when the count started
cpucycle_t fibre_startup_start = 0;
extern cpucycle_t fibre_switch_start;
cpucycle_t fibre_destroy_start = 0;

#endif
