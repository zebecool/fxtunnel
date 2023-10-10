#ifndef _FX_TYPEDEF__H_
#define _FX_TYPEDEF__H_


#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif //_CRT_SECURE_NO_WARNINGS

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif //_CRT_NONSTDC_NO_DEPRECATE

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif //_WINSOCK_DEPRECATED_NO_WARNINGS

#ifndef _SCL_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS
#endif //_SCL_SECURE_NO_WARNINGS
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <assert.h>
#include <string>
#include <fstream>
#include <iostream>
#include <stdarg.h> // va_start, etc.
#include <algorithm>
#include <future>
#include <vector>
#include <list>
#include <map>
#include <queue>
#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif
#include <thread> // std::thread
#include <shared_mutex>
#include <mutex> //std::mutex, std::unique_lock
#include <condition_variable>

#include "mjson.hpp"
using mjson = nlohmann::json;


#ifdef _WIN32
#include <tchar.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef _WIN32
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#endif

#include "logger.h"


#define BUF_SIZE  128 * 1024

#define malloc_msg(_len) calloc(_len,1)
#define zero_msg(_msg,_len) ::memset((char*)_msg, 0, _len)
#define fx_notused(V) ((void) V)

#ifdef _WIN32
static inline int gettimeofday(struct timeval* tp, void* tzp)
{
    SYSTEMTIME sys; GetLocalTime(&sys);

    time_t clock; struct tm tm; SYSTEMTIME wtm; GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900; tm.tm_mon = wtm.wMonth - 1; tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour; tm.tm_min = wtm.wMinute; tm.tm_sec = wtm.wSecond; tm.tm_isdst = -1;
    clock = mktime(&tm); tp->tv_sec = (long)clock; tp->tv_usec = wtm.wMilliseconds * 1000;
    return (0);
};
#endif

//get timestamp
static inline uint32_t get_now()
{
#ifdef _WIN32
    return (uint32_t)time(0);
#else
    time_t t1; time(&t1); return (uint32_t)t1;
#endif
};

//get current micro seconds count
static inline uint64_t get_now_msecs()
{
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t timestamp = tv.tv_sec; uint64_t usec = tv.tv_usec;
    uint64_t t = timestamp * 1000 + usec / 1000;
    return t;
};

//Generate unique 16 digit numbers
static inline uint64_t get_unique_16digit()
{
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t d16 = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec + tv.tv_usec / 1000;
    return d16;
};

//Using timestamp 10 bit seconds+3 bit milliseconds+3 bit microseconds+2 bit random numbers
static inline uint64_t get_digit18_uuid() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t timestamp = tv.tv_sec; uint64_t usec = tv.tv_usec;
    uint64_t t = timestamp * 1000000 + usec;
    gettimeofday(&tv, NULL);
    t = t * 100 + tv.tv_usec % 100;
    return t;
};

// sleep (micro seconds)
static inline void fx_sleep(int msec_timeout)
{
    //std::this_thread::sleep_for(std::chrono::milliseconds(msec_timeout));
#ifdef _WIN32
    Sleep(msec_timeout);
#else
    struct timeval t_timeval;
    t_timeval.tv_sec = msec_timeout / 1000;
    t_timeval.tv_usec = msec_timeout % 1000 * 1000;
    select(0, NULL, NULL, NULL, &t_timeval);
#endif
};

#ifndef _WIN32
static inline int _vscprintf(const char* format, va_list pargs) {
    int retval;
    va_list argcopy;
    va_copy(argcopy, pargs);
    retval = vsnprintf(NULL, 0, format, argcopy);
    va_end(argcopy);
    return retval;
};
#endif

//format string
static inline std::string std_format(const char* pszFmt, ...)
{
    std::string str; va_list args;
    va_start(args, pszFmt);
    {
        int nLength = _vscprintf(pszFmt, args);
        nLength += 1;  // include '\0' at end of string
        std::vector<char> vectorChars(nLength);
        vsnprintf(vectorChars.data(), nLength, pszFmt, args);
        str.assign(vectorChars.data());
    }
    va_end(args);
    return str;
};


class fxmutex
{
public:
    fxmutex() {};
    ~fxmutex() {};
    void lock() { mutex.lock(); };
    bool trylock() { return mutex.try_lock(); };
    void unlock() { mutex.unlock(); };
private:
    std::mutex mutex;
};
class fxrwlock
{
public:
    fxrwlock() {};
    ~fxrwlock() {};
    void lock_shared() { share_mutex.lock_shared(); };
    void unlock_shared() { share_mutex.unlock_shared(); };
    void lock() { share_mutex.lock(); };
    void unlock() { share_mutex.unlock(); };

    bool tryrdlock() { return share_mutex.try_lock_shared(); };
    bool trywrlock() { return share_mutex.try_lock(); };
private:
    std::shared_mutex share_mutex;
    bool share;
};

class queitem
{
public:
    queitem(int _type = 0) {
        type = _type; i_param = 0; ui_param = 0; i64_param = 0; u64_param = 0; b_param = false;
        token = 0; usid = 0; seid = 0; status = 0;
        ptr = NULL;
    };
    int type;
    int i_param; uint32_t ui_param; int64_t i64_param; uint64_t u64_param;
    bool b_param; std::string s_param;
    uint64_t token; uint64_t usid; uint64_t seid; int status;
    void* ptr;
};
class fxqueue
{
public:
    fxqueue() {};
    ~fxqueue() {};
    queitem* get() {
        if (que.size() <= 0) { return NULL; }
        mutex.lock(); queitem* item = que.front(); que.pop(); mutex.unlock();
        return item;
    };
    queitem* get(int timeout_msec) {
        queitem* item = NULL;
        if (que.size() <= 0) {
            std::unique_lock<std::mutex> ulock(mutex);
            if (timeout_msec == 0) {
                while (que.size() == 0) { cond.wait(ulock); }
            } else {
                cond.wait_for(ulock, std::chrono::milliseconds(timeout_msec));
                //while (cond.wait_for(ulock, std::chrono::milliseconds(timeout_msec)) == std::cv_status::timeout) {}
                if (que.size() == 0) { return NULL; }
            }
            ulock.unlock();
        }
        mutex.lock();
        if (que.size() > 0) { item = que.front(); que.pop(); }
        mutex.unlock();
        return item;
    };
    queitem* get_front() { queitem* item = NULL; mutex.lock(); if (que.size() > 0) { item = que.front(); } mutex.unlock(); return item; };
    void get_pop() { mutex.lock(); que.pop(); mutex.unlock(); };
    void put(queitem* item) { mutex.lock(); que.push(item); mutex.unlock(); cond.notify_all(); };
    int size() { int cnt = (int)que.size(); return cnt; };
    std::queue<queitem*> que;
    std::mutex mutex;
    std::condition_variable cond;
};

#endif


