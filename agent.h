#ifndef _FX_AGENT__H_
#define _FX_AGENT__H_

#include "sock.h"


//----------------------------------------------------------
// agent connection class
//----------------------------------------------------------
class agent;
class agentmgr;
class fxtunnel;

class agtconn : public fxsock
{
public:
    agtconn(uint64_t _seid, agent* _agt);
    ~agtconn();
public:
    agent* agt;
    uint64_t seid;
    bool peer_connected;
};

//----------------------------------------------------------
// agent class
//----------------------------------------------------------
class agent : public fxsock
{
public:
    agent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port, agentmgr* _amgr);
    ~agent();
    int init();
    agtconn* get_agtconn(uint64_t _seid);
    int get_session_count();
    void close_sessions();
    agtconn* accept_connect();
    void destroy_connect(agtconn* _agtc);
    int request_peer_connect(agtconn* _agtc);
    int notify_peer_disconnect(agtconn* _agtc);
public:
    agentmgr* amgr;
    uint64_t token;
    uint64_t usid;
    std::string name;
    std::map<uint64_t, agtconn*> agtconn_map; // seid <---> agentctl
};

//----------------------------------------------------------
// agent mgr class
//----------------------------------------------------------
class agentmgr
{
public:
    agentmgr(fxtunnel* _fxt);
    ~agentmgr();
    int init();
    agent* get_agent(uint64_t _usid);
    int active_agent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port);
    void destory_agent(uint64_t _usid);
    void notify_close_sessions(uint64_t _token);
    void notify_session_connect(msg_forwarding* _msg);
    void notify_session_disconnect(msg_forwarding* _msg);
    void notify_send_message(msg_forwarding* _msg);
    int select_task();
    void run();
    void stop();
public:
    fxtunnel* fxt;
    std::map<uint64_t, agent*> agent_map;  // usid <---> agent

    bool exit;  //thread exit flag
    std::thread* select_thread;

    fxqueue* tx_que;
    pairsock* pairfd;
};





//----------------------------------------------------------
// udp agent connection class
//----------------------------------------------------------
class udpagent;
class udpagentmgr;
class fxtunnel;

class udpagtconn
{
public:
    udpagtconn(uint64_t _seid, std::string _ipaddr, int _port, udpagent* _uagt);
    ~udpagtconn();
public:
    udpagent* uagt;
    uint64_t  seid;
    char      ipaddr[16];
    int       port;
    time_t    last_update;
};

//----------------------------------------------------------
// udp agent class
//----------------------------------------------------------
class udpagent : public fxudpsock
{
public:
    udpagent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port, udpagentmgr* _uamgr);
    ~udpagent();
    int init();
    udpagtconn* get_uagtconn(uint64_t _seid);
    int get_session_count();
    void close_sessions();
    void destroy_connect(udpagtconn* _uagtc);
    int request_peer_connect(udpagtconn* _uagtc);
    int notify_peer_disconnect(udpagtconn* _uagtc);
public:
    udpagentmgr* uamgr;
    uint64_t token;
    uint64_t usid;
    std::string name;
    std::map<std::string, udpagtconn*> ipport_uagtconn_map;  //ip+port <---> udpagtconn
    std::map<uint64_t, udpagtconn*> uagtconn_map; // seid <---> udpagtconn
};

//----------------------------------------------------------
// udp agent mgr class
//----------------------------------------------------------
class udpagentmgr
{
public:
    udpagentmgr(fxtunnel* _fxt);
    ~udpagentmgr();
    int init();
    udpagent* get_uagent(uint64_t _usid);
    int active_uagent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port);
    void destory_uagent(uint64_t _usid);
    void notify_session_connect(msg_forwarding* _msg);
    void notify_session_disconnect(msg_forwarding* _msg);
    void notify_send_message(msg_forwarding* _msg);
    int select_task();
    void run();
    void stop();
public:
    fxtunnel* fxt;
    std::map<uint64_t, udpagent*> uagent_map;  // usid <---> agent

    bool exit;  //thread exit flag
    std::thread* select_thread;

    fxqueue* tx_que;
    pairsock* pairfd;
};


#endif
