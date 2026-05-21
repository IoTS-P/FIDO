#pragma once

#include <errno.h>
#include <string.h>

#define ERRSTR() (strerror(errno))
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#ifdef NDEBUG
    #define FW_LOG_DBG(fmt, ...)
    #define FW_LOG_INFO(fmt, ...)
#else
    #define FW_LOG_DBG(fmt, ...) (fw_log(0, "[DBG] %s:%d | " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__))
    #define FW_LOG_INFO(fmt, ...) (fw_log(1, "[INFO] %s:%d | " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__))
#endif

#define FW_LOG_WARNING(fmt, ...) (fw_log(2, "[WARNING] %s:%d | " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__))
#define FW_LOG_ERROR(fmt, ...) (fw_log(3, "[ERROR] (%s) %s:%d | " fmt, strerror(errno), __FILENAME__, __LINE__, ## __VA_ARGS__))

#define FW_ASSERT_NOT_REACHED(fmt, ...) FW_LOG_ERROR("assertion: " fmt, ## __VA_ARGS__); abort();
#define FW_ASSERT(expr, fmt, ...) if (!(expr)) {FW_LOG_ERROR("assertion failed `" #expr "`: " fmt, ## __VA_ARGS__); abort();}
#define FW_ASSERT1(expr) if (!(expr)) {FW_LOG_ERROR("assertion failed `" #expr "`\n"); abort();}

#define FW_LOGLEVEL_NONE 4
void fw_log(const int level, const char *frmt, ...);

