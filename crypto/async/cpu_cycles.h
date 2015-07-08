
#ifndef HEADER_CPU_CYCLES_COUNT_H
# define HEADER_CPU_CYCLES_COUNT_H

#define QAT_CPU_CYCLES_COUNT

#ifdef QAT_CPU_CYCLES_COUNT

typedef unsigned long long cpucycle_t;

// This implementation is from speed
extern unsigned long long rdtsc(void);

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

// For every operation I keep track of an accumulator + counter
extern cpucycle_t fibre_startup_acc;
extern unsigned int fibre_startup_num;

extern cpucycle_t fibre_switch_acc;
extern unsigned int fibre_switch_num;

extern cpucycle_t fibre_destroy_acc;
extern unsigned int fibre_destroy_num;

extern cpucycle_t fibre_total_acc;
extern unsigned int fibre_total_num;


// Size of the sample used to calculate the average
// Values are printed only after collecting QAT_FIBRE_*_SAMPLE values
#define QAT_FIBRE_STARTUP_SAMPLE 20000
#define QAT_FIBRE_SWITCH_SAMPLE 20000
#define QAT_FIBRE_DESTROY_SAMPLE 20000
#define QAT_FIBRE_TOTAL_SAMPLE 20000

#define QAT_FIBRE_CYCLES_MIN 999999

// TODO are we interested in these?
// I think they are useful to detect anomalies
extern cpucycle_t fibre_startup_min;
extern cpucycle_t fibre_startup_max;

extern cpucycle_t fibre_switch_min;
extern cpucycle_t fibre_switch_max;

extern cpucycle_t fibre_destroy_min;
extern cpucycle_t fibre_destroy_max;

extern cpucycle_t fibre_total_min;
extern cpucycle_t fibre_total_max;

// I also need to remember when the count started
extern cpucycle_t fibre_startup_start;
extern cpucycle_t fibre_switch_start;
extern cpucycle_t fibre_destroy_start;
extern cpucycle_t fibre_total_start;

// I keep track of the number of outliers
// http://stackoverflow.com/q/19941588/556141
extern unsigned int fibre_startup_out;
extern unsigned int fibre_switch_out;
extern unsigned int fibre_destroy_out;
extern unsigned int fibre_total_out;

// This is the previous average
extern cpucycle_t fibre_startup_avg;
extern cpucycle_t fibre_switch_avg;
extern cpucycle_t fibre_destroy_avg;
extern cpucycle_t fibre_total_avg;
#endif

#endif /* HEADER_CPU_CYCLES_COUNT_H */

