
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

#define QAT_FIBRE_STARTUP_SAMPLE 2000
#define QAT_FIBRE_SWITCH_SAMPLE 2000
#define QAT_FIBRE_DESTROY_SAMPLE 2000

#define QAT_FIBRE_CYCLES_MIN 999999


// TODO are we interested in these?
// I think they are useful to detect anomalies
cpucycle_t fibre_startup_min = QAT_FIBRE_CYCLES_MIN;
cpucycle_t fibre_startup_max = 0;

cpucycle_t fibre_switch_min = QAT_FIBRE_CYCLES_MIN;
cpucycle_t fibre_switch_max = 0;

cpucycle_t fibre_destroy_min = QAT_FIBRE_CYCLES_MIN;
cpucycle_t fibre_destroy_max = 0;

// I also need to remember when the count started
cpucycle_t fibre_startup_start = 0;
extern cpucycle_t fibre_switch_start;
cpucycle_t fibre_destroy_start = 0;

// I keep track of the number of outliers
// http://stackoverflow.com/q/19941588/556141
unsigned int fibre_startup_out = 0;
unsigned int fibre_switch_out = 0;
unsigned int fibre_destroy_out = 0;

// This is the previous average
cpucycle_t fibre_startup_avg = 0;
cpucycle_t fibre_switch_avg = 0;
cpucycle_t fibre_destroy_avg = 0;
#endif



