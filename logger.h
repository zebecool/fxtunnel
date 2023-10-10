#ifndef _FX_LOGGER__H_
#define _FX_LOGGER__H_

enum {
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
};

static inline int get_log_level(std::string _level_s)
{
    if (_level_s == "trace") return LOG_TRACE;
    else if (_level_s == "debug") return LOG_DEBUG;
    else if (_level_s == "info") return LOG_INFO;
    else if (_level_s == "warn") return LOG_WARN;
    else if (_level_s == "error") return LOG_ERROR;
    else if (_level_s == "fatal") return LOG_FATAL;
    return LOG_ERROR;
};

extern int log_level;
static inline void log_write(int level, const char* fmt, ...) {
    if (level < log_level) { return; }
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    std::vector<char> vec(len + 1);
    va_start(args, fmt);
    std::vsnprintf(&vec[0], len + 1, fmt, args);
    va_end(args);

    char time_s[64];
#ifdef WIN32
    SYSTEMTIME sys; GetLocalTime(&sys);
    sprintf(time_s, "%4d-%02d-%02d %02d:%02d:%02d.%03d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
#else
    struct tm ptm; struct timeval tv; gettimeofday(&tv, NULL); localtime_r(&tv.tv_sec, &ptm);
    sprintf(time_s, "%04d-%02d-%02d %02d:%02d:%02d.%03d", ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec, (int)(tv.tv_usec / 1000));
#endif

    std::string log_s = time_s; log_s += vec.data();
    std::cout << log_s << std::endl;
    fflush(stdout);
};

#ifdef _WIN32
#define logp(fmt, ...)      fprintf(stdout,"" fmt "\n", ##__VA_ARGS__)
#define logt(fmt, ...)      log_write(LOG_TRACE, " [TT] " fmt, ##__VA_ARGS__)
#define logd(fmt, ...)      log_write(LOG_DEBUG, " [DD] " fmt, ##__VA_ARGS__)
#define logit(fmt, ...)     log_write(LOG_INFO,  " [II] " fmt, ##__VA_ARGS__)

#define logt_ffl(fmt, ...)  log_write(LOG_TRACE, " [TT][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__)
#define logd_ffl(fmt, ...)  log_write(LOG_DEBUG, " [DD][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__)
#define logit_ffl(fmt, ...) log_write(LOG_INFO,  " [II][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__)

#define logw(fmt, ...)      log_write(LOG_WARN,  " [WW][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__)
#define logerr(fmt, ...)    log_write(LOG_ERROR, " [EE][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__)
#define syserr(fmt, ...)    log_write(LOG_FATAL, " [SS][%s@%s:%d] " fmt ", error: %d. reason is: %s. ",__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__,errno,strerror(errno))

#define fx_assert(result,fmt,...) \
    do { \
        if (!(result)) { \
            log_write(LOG_FATAL,  " [FF][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##__VA_ARGS__); \
            fflush(stderr); \
            _exit(-1); \
        } \
    } while (0)

#else

#define logp(fmt,args...)      fprintf(stdout,"" fmt "\n", ##args)
#define logt(fmt,args...)      log_write(LOG_TRACE, " [TT] " fmt, ##args)
#define logd(fmt,args...)      log_write(LOG_DEBUG, " [DD] " fmt, ##args)
#define logit(fmt,args...)     log_write(LOG_INFO,  " [II] " fmt, ##args)

#define logt_ffl(fmt, args...) log_write(LOG_TRACE, " [TT][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args)
#define logd_ffl(fmt,args...)  log_write(LOG_DEBUG, " [DD][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args)
#define logit_ffl(fmt,args...) log_write(LOG_INFO,  " [II][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args)

#define logw(fmt,args...)      log_write(LOG_WARN,  " [WW][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args)
#define logerr(fmt,args...)    log_write(LOG_ERROR, " [EE][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args)
#define syserr(fmt,args...)    log_write(LOG_FATAL, " [SS][%s@%s:%d] " fmt ", error: %d. reason is: %s. ",__FUNCTION__,__FILE__,__LINE__,##args,errno,strerror(errno))

#define fx_assert(result,fmt,args...) \
    do { \
        if (!(result)) { \
            log_write(LOG_FATAL,  " [FF][%s@%s:%d] " fmt,__FUNCTION__,__FILE__,__LINE__,##args); \
            fflush(stderr); \
            _exit(-1); \
        } \
    } while (0)

#endif


#endif
