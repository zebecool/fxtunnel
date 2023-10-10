#ifndef _FX_CONNECTOR__H_
#define _FX_CONNECTOR__H_

#include "sock.h"

//----------------------------------------------------------
// connection ctl class
//----------------------------------------------------------
class conn;
class connmgr;
class fxtunnel;

class connclt : public fxsock
{
public:
    connclt(uint64_t _seid, conn* _c);
    ~connclt();
public:
    conn* c;
    uint64_t seid;
};


//----------------------------------------------------------
// conn class
//----------------------------------------------------------
class conn
{
public:
    conn(uint64_t token, uint64_t _usid, std::string _addr, int _port, std::string _name, connmgr* _cmgr);
    ~conn();
    int init();
    connclt* get_connclt(uint64_t _seid);
    std::string get_connect_ipaddr() { return connect_ipaddr; };
    int get_session_count();
    void close_sessions();
    int notify_connect_state(uint64_t _seid, int _cmd);
public:
    connmgr* cmgr;
    uint64_t token;
    uint64_t usid;
    std::string name;
    std::string connect_addr;
    std::string connect_ipaddr;
    int connect_port;
    std::map<uint64_t, connclt*> connclt_map; // seid <---> connclt
};


//----------------------------------------------------------
// conn mgr class
//----------------------------------------------------------
class connmgr
{
public:
    connmgr(fxtunnel* _fxt);
    ~connmgr();
    int init();
    conn* get_conn(uint64_t _usid);
    int active_conn(uint64_t _token, uint64_t _usid, std::string _name, std::string _addr, int _port);
    void destory_conn(uint64_t _usid);
    void notify_close_sessions(uint64_t _token);
    void notify_create_session(msg_forwarding* _msg);
    void notify_session_disconnect(msg_forwarding* _msg);
    void notify_send_message(msg_forwarding* _msg);

    int connect_task();
    //int connect_task_2();
    int select_task();
    void run();
    void stop();
public:
    fxtunnel* fxt;
    std::map<uint64_t, conn*> conn_map; // usid <---> conn

    bool exit;  //thread exit flag
    std::thread* connect_thread;
    std::thread* select_thread;

    fxqueue* connect_que;
    fxqueue* tx_que;
    pairsock* pairfd;
};




//----------------------------------------------------------
// udp connection ctl class
//----------------------------------------------------------
class udpconn;
class udpconnmgr;
class fxtunnel;

class udpconnclt : public fxudpsock
{
public:
    udpconnclt(uint64_t _seid, udpconn* _c);
    ~udpconnclt();
public:
    udpconn* uc;
    uint64_t seid;
};


//----------------------------------------------------------
// udpconn class
//----------------------------------------------------------
class udpconn
{
public:
    udpconn(uint64_t token, uint64_t _usid, std::string _addr, int _port, std::string _name, udpconnmgr* _ucmgr);
    ~udpconn();
    int init();
    udpconnclt* get_uconnclt(uint64_t _seid);
    std::string get_connect_ipaddr() { return connect_ipaddr; };
    int get_session_count();
    void close_sessions();
    int notify_connect_state(uint64_t _seid, int _cmd);
public:
    udpconnmgr* ucmgr;
    uint64_t token;
    uint64_t usid;
    std::string name;
    std::string connect_addr;
    std::string connect_ipaddr;
    int connect_port;
    std::map<uint64_t, udpconnclt*> uconnclt_map; // seid <---> connclt
};


//----------------------------------------------------------
// udp conn mgr class
//----------------------------------------------------------
class udpconnmgr
{
public:
    udpconnmgr(fxtunnel* _fxt);
    ~udpconnmgr();
    int init();
    udpconn* get_uconn(uint64_t _seid);
    int active_uconn(uint64_t _token, uint64_t _usid, std::string _name, std::string _addr, int _port);
    void destory_uconn(uint64_t _usid);

    void notify_create_session(msg_forwarding* _msg);
    void notify_session_disconnect(msg_forwarding* _msg);
    void notify_send_message(msg_forwarding* _msg);

    int select_task();
    void run();
    void stop();
public:
    fxtunnel* fxt;
    std::map<uint64_t, udpconn*> uconn_map; // usid <---> conn

    bool exit;  //thread exit flag
    std::thread* select_thread;

    fxqueue* tx_que;
    pairudpsock* pairfd;
};


#endif


