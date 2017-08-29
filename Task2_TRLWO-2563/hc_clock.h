#ifndef __HC_CLOCK_H__
#define __HC_CLOCK_H__

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long hc_clock_t;

inline static hc_clock_t hc_clock_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now))
    {
        fprintf(stderr, "CLOCK_MONOTONIC is not supported by platform");
        abort();
    }

    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

#endif
