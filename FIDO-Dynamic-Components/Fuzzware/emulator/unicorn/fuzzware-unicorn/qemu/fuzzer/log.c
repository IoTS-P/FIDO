#include "log.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/syscall.h>

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

//1GB
#define MAX_LOG_SIZE (2<<29)

static int min_log_level = -1;

void fw_log(const int level, const char *frmt, ...)
{
    if (unlikely(min_log_level == -1)) {
        const char *tmp = getenv("IF_LOG_LEVEL");
        if (!tmp)
            min_log_level = FW_LOGLEVEL_NONE;
        else
            min_log_level = atoi(tmp);
    }

    if (likely(level < min_log_level)) {
        return;
    }

    va_list argptr;
    va_start(argptr, frmt);
    struct timeval tv;
    struct timezone tz;

    bool fail = true;
    if(gettimeofday(&tv, &tz) == 0) {
        struct tm tm;
        if(localtime_r(&tv.tv_sec, &tm) != NULL) {
            fprintf(stderr, "(%04d/%02d/%02d %02d:%02d:%02d:%06ld)(%d/%ld): ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, (int)getpid(), syscall(SYS_gettid));
            fail = false;
        }
    }

    if(fail)
        fprintf(stderr, "(%jd): ", (intmax_t) time(0));

    vfprintf(stderr, frmt, argptr);
    va_end(argptr);
    fflush(NULL);
    return;
}
