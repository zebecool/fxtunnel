#include "typedef.h"
#include "agent.h"
#include "fxtunnel.h"


agtconn::agtconn(uint64_t _seid, agent* _agt)
{
    seid = _seid; agt = _agt; peer_connected = false;
}
agtconn::~agtconn()
{
}


agent::agent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port, agentmgr* _amgr)
{
    token = _token; usid = _usid; name = _name; listen_port = _listen_port; amgr = _amgr;
}
agent::~agent()
{
    close_sessions();
}
int agent::init()
{
    int ret = _init_server();
    if (ret != 0) { logerr("agent _init_server( %d ) failure", listen_port); return -1; }
    //logd("agent[ %llu : %s : %llu ] running, listening on port %d", usid, name.c_str(), token, listen_port);
    return 0;
}
agtconn* agent::get_agtconn(uint64_t _seid)
{
    agtconn* agtc = NULL;
    auto iter = agtconn_map.find(_seid);
    if (iter != agtconn_map.end()) {
        agtc = iter->second;
    }
    return agtc;
}
int agent::get_session_count()
{
    return agtconn_map.size();
}
void agent::close_sessions()
{
    agtconn* agtc = NULL;
    for (auto& iter : agtconn_map) {
        agtc = iter.second;
        agtc->_close();
        delete agtc;
    }
    agtconn_map.clear();
}
agtconn* agent::accept_connect()
{
    uint64_t seid = get_unique_16digit();
    agtconn* agtc = new agtconn(seid, this);
    int ret = agtc->_accept(sock);
    if (ret < 0) { delete agtc; return NULL; }
    agtconn_map[agtc->seid] = agtc;
    //logit("agent accept connection. [ %s : %d ] usid[ %llu ] seid[ %llu ]", agtc->ipaddr.c_str(), agtc->port, usid, agtc->seid);
    return agtc;
}
void agent::destroy_connect(agtconn* _agtc)
{
    _agtc->_close();
    agtconn_map.erase(_agtc->seid);
    delete _agtc;
}
int agent::request_peer_connect(agtconn* _agtc)
{
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _agtc->seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, MSG_CMD__TCP_CONNECT, 0);
    queitem* qitem = new queitem();
    qitem->ptr = msg_fw;
    amgr->fxt->send_notify(qitem);
    return 0;
}
int agent::notify_peer_disconnect(agtconn* _agtc)
{
    if (!_agtc->peer_connected) { return 0; }
    queitem* qitem = new queitem(0);
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _agtc->seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, MSG_CMD__TCP_DISCONNECT, 0);
    qitem->ptr = msg_fw;
    amgr->fxt->send_notify(qitem);
    return 0;
}


agentmgr::agentmgr(fxtunnel* _fxt)
{
	fxt = _fxt;
    tx_que = new fxqueue(); pairfd = new pairsock(tx_que);
}
agentmgr::~agentmgr()
{
    for (auto& iter : agent_map) {
        iter.second->close_sessions();
        delete iter.second;
    }
    agent_map.clear();
}
int agentmgr::init()
{
	return 0;
}
agent* agentmgr::get_agent(uint64_t _usid)
{
    agent* agt = NULL;
    auto iter = agent_map.find(_usid);
    if (iter != agent_map.end()) {
        agt = iter->second;
    }
    return agt;
}
int agentmgr::active_agent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port)
{
    agent* agt = get_agent(_usid); if (agt) { return 0; }
    agt = new agent(_token, _usid, _name, _listen_port, this);
    int ret = agt->init(); if (ret < 0) { delete agt; return 0; }
    queitem* qitem = new queitem(100);
    qitem->ptr = agt;
    pairfd->notify(qitem);
	return 0;
}
void agentmgr::destory_agent(uint64_t _usid)
{
    queitem* qitem = new queitem(101);
    qitem->usid = _usid;
    pairfd->notify(qitem);
}
void agentmgr::notify_close_sessions(uint64_t _token)
{
    queitem* qitem = new queitem(102);
    qitem->token = _token;
    pairfd->notify(qitem);
}
void agentmgr::notify_session_connect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(103);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void agentmgr::notify_session_disconnect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(104);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void agentmgr::notify_send_message(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(0);
    char* ptr = (char*)malloc(_msg->header.length); fx_assert(ptr, "malloc failed");
    ::memcpy(ptr, (char*)_msg, _msg->header.length);
    qitem->ptr = ptr;
    pairfd->notify(qitem);
}
int agentmgr::select_task()
{
    int ret = 0; agent* agt; agtconn* agtc; int maxfd = 0; fd_set rfds; struct timeval tv;
    queitem* qitem; char* ptr; msg_forwarding* msg_fw; std::list<agtconn*> agtc_list;
    while (!exit) {
        time_t t = get_now();
        agtc_list.clear();
        FD_ZERO(&rfds);
        FD_SET(pairfd->rx_fd, &rfds); maxfd = pairfd->rx_fd;
        for (auto iter = agent_map.begin(); iter != agent_map.end(); iter++) {
            agt = iter->second;
            FD_SET(agt->sock, &rfds); if (agt->sock > maxfd) { maxfd = agt->sock; }
            for (auto it = agt->agtconn_map.begin(); it != agt->agtconn_map.end();) {
                agtc = it->second;
                if (!agtc->is_connected() || (!agtc->peer_connected && t - agtc->last_update > 7)) {
                    if (agtc->is_connected()) agtc->_close();
                    agt->notify_peer_disconnect(agtc); agt->agtconn_map.erase(it++); delete agtc; continue;
                }
                if (agtc->peer_connected) {
                    FD_SET(agtc->sock, &rfds); if (agtc->sock > maxfd) { maxfd = agtc->sock; }
                    agtc_list.push_back(agtc);
                }
                it++;
            }
        }
        tv.tv_sec = 0; tv.tv_usec = 100 * 1000;
        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret == 0) { continue; }
        else if (ret < 0) { syserr("::select()"); break; }
        for (auto iter : agent_map) {
            agt = iter.second;
            if (FD_ISSET(agt->sock, &rfds)) {
                agtc = agt->accept_connect();
                if (agtc) {
                    //request new connect
                    agt->request_peer_connect(agtc);
                }
            }
        }
        for (auto& iter : agtc_list) {
            agtc = iter;
            if (FD_ISSET(agtc->sock, &rfds)) {
                ret = agtc->_read();
                if (ret > 0) {
                    //logt("Recv data from Agent client[ %s : %d ] length[ %u ] seid[ %llu ]", agtc->ipaddr.c_str(), agtc->port, agtc->r_buf_pos, agtc->seid);
                    int mlen = msg_forwarding_len + agtc->r_buf_pos;
                    msg_fw = (msg_forwarding*)malloc_msg(mlen);
                    pack_msg(msg_fw, mlen, agtc->agt->token, MSG_T__FORWARD, agtc->agt->usid, agtc->seid);
                    pack_forwarding(msg_fw, MSG_SUB__TCP_FORWARDING, MSG_CMD__FORWARDING, 0);
                    msg_fw->datalen = agtc->r_buf_pos;
                    memcpy(forwarding_msg(msg_fw), agtc->r_buf, msg_fw->datalen);
                    qitem = new queitem();
                    qitem->ptr = msg_fw;
                    fxt->send_notify(qitem);
                }
                agtc->r_buf_pos = 0;
            }
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            pairfd->release();
            while (!exit) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                if (qitem->type == 100) {
                    //add agent
                    agt = (agent*)qitem->ptr;
                    agent_map[agt->usid] = agt;
                    logit("active agent. usid[ %llu : %s ] listen port[ %d ] token[ %llu ]", agt->usid, agt->name.c_str(), agt->listen_port, agt->token);
                }
                else if (qitem->type == 101) {
                    //delete agent
                    agt = get_agent(qitem->usid);
                    if (agt) {
                        agt->close_sessions();
                        logit("destory agent. usid[ %llu : %s ] listen port[ %d ]", agt->usid, agt->name.c_str(), agt->listen_port);
                        delete agt;
                        agent_map.erase(qitem->usid);
                    }
                }
                else if (qitem->type == 102) {
                    //close all sessions
                    for (auto& iter : agent_map) {
                        if (iter.second->token == qitem->token) {
                            iter.second->close_sessions();
                        }
                    }
                }
                else if (qitem->type == 103) {
                    //process peer connected
                    agt = get_agent(qitem->usid);
                    if (agt) {
                        agtc = agt->get_agtconn(qitem->seid);
                        if (agtc) {
                            agtc->peer_connected = true;
                            logt("agent accept connection. [ %s : %d ] usid[ %llu ] seid[ %llu ]", agtc->ipaddr.c_str(), agtc->port, agt->usid, agtc->seid);
                        }
                    }
                }
                else if (qitem->type == 104) {
                    //process peer disconnect
                    agt = get_agent(qitem->usid);
                    if (agt) {
                        agtc = agt->get_agtconn(qitem->seid);
                        if (agtc) {
                            agtc->peer_connected = false;
                            agtc->_close();
                        }
                    }
                }
                else if (qitem->type == 0) {
                    msg_fw = (msg_forwarding*)qitem->ptr;
                    ptr = forwarding_msg(msg_fw);
                    agt = get_agent(msg_fw->header.usid);
                    if (agt) {
                        agtc = agt->get_agtconn(msg_fw->header.seid);
                        if (agtc) {
                            agtc->_write(ptr, msg_fw->datalen);
                        } else {
                            logt("Not found agtconn. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                        }
                    } else {
                        logw("Not found agent. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                    }
                    free(qitem->ptr);
                }
                else {
                    logw(" agentmgr::select_task() Unknown queitem type[ %d ]", qitem->type);
                }
                delete qitem;
            }
        }
    }
    //close all session
    for (auto& iter : agent_map) {
        agt = iter.second;
        for (auto& it : agt->agtconn_map) {
            it.second->_close();
            delete it.second;
        }
        agt->agtconn_map.clear();
        delete agt;
    }
    agent_map.clear();
    //clean queue
    while (true) {
        queitem* qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
        free(qitem->ptr); delete qitem;
    }
    return 0;
}
void agentmgr_select_thread(agentmgr* _amgr)
{
    logd("start agentmgr select_task");
    _amgr->select_task();
    logd("exit agentmgr select_task");
}

void agentmgr::run()
{
    exit = false;
    select_thread = new std::thread(agentmgr_select_thread, this);
}
void agentmgr::stop()
{
    exit = true;
    logd("Wait connmgr select thread exit");
    select_thread->join();
    delete select_thread; select_thread = NULL;
}





udpagtconn::udpagtconn(uint64_t _seid, std::string _ipaddr, int _port, udpagent* _uagt)
{
    seid = _seid; strcpy(ipaddr, _ipaddr.c_str()); port = _port; uagt = _uagt;
}
udpagtconn::~udpagtconn()
{
}


udpagent::udpagent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port, udpagentmgr* _uamgr)
{
    token = _token; usid = _usid; name = _name; listen_port = _listen_port; uamgr = _uamgr;
}
udpagent::~udpagent()
{
    close_sessions();
}
int udpagent::init()
{
    int ret = _init_server();
    if (ret != 0) { logerr("udpagent _init_server( %d ) failure", listen_port); return -1; }
    //logd("udpagent[ %llu : %s : %llu ] running, listening on port %d", usid, name.c_str(), token, listen_port);
    return 0;
}
udpagtconn* udpagent::get_uagtconn(uint64_t _seid)
{
    udpagtconn* uagtc = NULL;
    auto iter = uagtconn_map.find(_seid);
    if (iter != uagtconn_map.end()) {
        uagtc = iter->second;
    }
    return uagtc;
}
int udpagent::get_session_count()
{
    return uagtconn_map.size();
}
void udpagent::close_sessions()
{
    udpagtconn* uagtc = NULL;
    for (auto& iter : uagtconn_map) {
        uagtc = iter.second;
        delete uagtc;
    }
    uagtconn_map.clear();
}
void udpagent::destroy_connect(udpagtconn* _uagtc)
{
    std::string agctl_key = std_format("%s-%d", _uagtc->ipaddr, _uagtc->port);
    ipport_uagtconn_map.erase(agctl_key);
    uagtconn_map.erase(_uagtc->seid);
    delete _uagtc;
}
int udpagent::request_peer_connect(udpagtconn* _uagtc)
{
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _uagtc->seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, MSG_CMD__UDP_CONNECT, 0);
    queitem* qitem = new queitem();
    qitem->ptr = msg_fw;
    uamgr->fxt->send_notify(qitem);
    return 0;
}
int udpagent::notify_peer_disconnect(udpagtconn* _uagtc)
{
    queitem* qitem = new queitem(0);
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _uagtc->seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, MSG_CMD__UDP_DISCONNECT, 0);
    qitem->ptr = msg_fw;
    uamgr->fxt->send_notify(qitem);
    return 0;
}


udpagentmgr::udpagentmgr(fxtunnel* _fxt)
{
    fxt = _fxt;
    tx_que = new fxqueue(); pairfd = new pairsock(tx_que);
}
udpagentmgr::~udpagentmgr()
{
    for (auto& iter : uagent_map) {
        iter.second->close_sessions();
        delete iter.second;
    }
    uagent_map.clear();
}
int udpagentmgr::init()
{
    return 0;
}
udpagent* udpagentmgr::get_uagent(uint64_t _usid)
{
    udpagent* uagt = NULL;
    auto iter = uagent_map.find(_usid);
    if (iter != uagent_map.end()) {
        uagt = iter->second;
    }
    return uagt;
}
int udpagentmgr::active_uagent(uint64_t _token, uint64_t _usid, std::string _name, int _listen_port)
{
    udpagent* agt = get_uagent(_usid); if (agt) { return 0; }
    agt = new udpagent(_token, _usid, _name, _listen_port, this);
    int ret = agt->init(); if (ret < 0) { delete agt; return -1; }
    queitem* qitem = new queitem(100);
    qitem->ptr = agt;
    pairfd->notify(qitem);
    return 0;
}
void udpagentmgr::destory_uagent(uint64_t _usid)
{
    queitem* qitem = new queitem(101);
    qitem->usid = _usid;
    pairfd->notify(qitem);
}
void udpagentmgr::notify_session_connect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(103);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void udpagentmgr::notify_session_disconnect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(104);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void udpagentmgr::notify_send_message(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(0);
    char* ptr = (char*)malloc(_msg->header.length); fx_assert(ptr, "malloc failed");
    ::memcpy(ptr, (char*)_msg, _msg->header.length);
    qitem->ptr = ptr;
    pairfd->notify(qitem);
}
int udpagentmgr::select_task()
{
    int ret = 0; udpagent* uagt; udpagtconn* uagtc; int maxfd = 0; fd_set rfds; struct timeval tv;
    queitem* qitem; char* ptr; msg_forwarding* msg_fw;
    while (!exit) {
        time_t t = get_now();
        FD_ZERO(&rfds);
        FD_SET(pairfd->rx_fd, &rfds); maxfd = pairfd->rx_fd;
        for (auto iter = uagent_map.begin(); iter != uagent_map.end(); iter++) {
            uagt = iter->second;
            FD_SET(uagt->sock, &rfds); if (uagt->sock > maxfd) { maxfd = uagt->sock; }
            for (auto it = uagt->uagtconn_map.begin(); it != uagt->uagtconn_map.end();) {
                uagtc = it->second;
                if (t - uagtc->last_update > 120) {
                    // notify peer disconnect
                    uagt->notify_peer_disconnect(uagtc);
                    std::string agctl_key = std_format("%s-%d", uagtc->ipaddr, uagtc->port); uagt->ipport_uagtconn_map.erase(agctl_key);
                    uagt->uagtconn_map.erase(it++);
                    delete uagtc; continue;
                }
                it++;
            }
        }
        tv.tv_sec = 0; tv.tv_usec = 100 * 1000;
        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret == 0) { continue; }
        else if (ret < 0) { syserr("::select()"); break; }
        for (auto iter : uagent_map) {
            uagt = iter.second;
            if (!FD_ISSET(uagt->sock, &rfds)) continue;
            char ipaddr[32]; int port;
            int rlen = uagt->_read_buf(ipaddr, &port);
            if (rlen > 0) {
                //logt("udpagent recv data from client[ %s : %d ] length[ %u ]", ipaddr, port, rlen);
                std::string agctl_key = std_format("%s-%d", ipaddr, port);
                auto it = uagt->ipport_uagtconn_map.find(agctl_key);
                if (it != uagt->ipport_uagtconn_map.end()) {
                    uagtc = it->second;
                } else {
                    uint64_t seid = get_unique_16digit();
                    uagtc = new udpagtconn(seid, ipaddr, port, uagt);
                    uagt->ipport_uagtconn_map[agctl_key] = uagtc;
                    uagt->uagtconn_map[uagtc->seid] = uagtc;
                    // request peer connect
                    uagt->request_peer_connect(uagtc);
                }
                uagtc->last_update = get_now();
                //logt("Recv data from udpagent client[ %s : %d ] length[ %u ] seid[ %llu ]", ipaddr, port, rlen, uagtc->seid);
                int mlen = msg_forwarding_len + rlen;
                msg_fw = (msg_forwarding*)malloc_msg(mlen);
                pack_msg(msg_fw, mlen, uagt->token, MSG_T__FORWARD, uagt->usid, uagtc->seid);
                pack_forwarding(msg_fw, MSG_SUB__UDP_FORWARDING, MSG_CMD__FORWARDING, 0);
                msg_fw->datalen = rlen;
                memcpy(forwarding_msg(msg_fw), uagt->r_buf, msg_fw->datalen);
                qitem = new queitem();
                qitem->ptr = msg_fw;
                fxt->send_notify(qitem);
            }
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            pairfd->release();
            while (true) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                if (qitem->type == 100) {
                    //add agent
                    uagt = (udpagent*)qitem->ptr;
                    uagent_map[uagt->usid] = uagt;
                    logit("active udpagent. usid[ %llu : %s ] listen port[ %d ] token[ %llu ]", uagt->usid, uagt->name.c_str(), uagt->listen_port, uagt->token);
                }
                else if (qitem->type == 101) {
                    //delete agent
                    uagt = get_uagent(qitem->usid);
                    if (uagt) {
                        uagt->close_sessions();
                        logit("destory udpagent. usid[ %llu : %s ] listen port[ %d ]", uagt->usid, uagt->name.c_str(), uagt->listen_port);
                        delete uagt;
                        uagent_map.erase(qitem->usid);
                    }
                }
                else if (qitem->type == 102) {
                    //close_sessions
                    uagt = get_uagent(qitem->usid);
                    if (uagt) {
                        uagt->close_sessions();
                    }
                }
                else if (qitem->type == 103) {
                    //process peer connected
                    uagt = get_uagent(qitem->usid);
                    if (uagt) {
                        uagtc = uagt->get_uagtconn(qitem->seid);
                        if (uagtc) {
                            uagtc->last_update = get_now();
                        }
                    }
                }
                else if (qitem->type == 104) {
                    //process peer disconnect
                    uagt = get_uagent(qitem->usid);
                    if (uagt) {
                        uagtc = uagt->get_uagtconn(qitem->seid);
                        if (uagtc) {
                            uagt->destroy_connect(uagtc);
                        }
                    }
                }
                else if (qitem->type == 0) {
                    msg_fw = (msg_forwarding*)qitem->ptr;
                    ptr = forwarding_msg(msg_fw);
                    uagt = get_uagent(msg_fw->header.usid);
                    if (uagt) {
                        uagtc = uagt->get_uagtconn(msg_fw->header.seid);
                        if (uagtc) {
                            uagt->_send_buf(uagtc->ipaddr, uagtc->port, ptr, msg_fw->datalen);
                        } else {
                            logd("Not found udpagtconn. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                        }
                    } else {
                        logd("Not found udpagent. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                    }
                    free(qitem->ptr);
                } else {
                    logw(" udpagentmgr::select_task() Unknown queitem type[ %d ]", qitem->type);
                }
                delete qitem;
            }
        }
    }
    //close all session
    for (auto& iter : uagent_map) {
        uagt = iter.second;
        uagt->close_sessions();
        delete uagt;
    }
    uagent_map.clear();
    //clean queue
    while (true) {
        queitem* qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
        free(qitem->ptr); delete qitem;
    }
    return 0;
}
void udpagentmgr_select_thread(udpagentmgr* _amgr)
{
    logd("start udpagentmgr select_task");
    _amgr->select_task();
    logd("exit udpagentmgr select_task");
}

void udpagentmgr::run()
{
    exit = false;
    select_thread = new std::thread(udpagentmgr_select_thread, this);
}
void udpagentmgr::stop()
{
    exit = true;
    logd("Wait connmgr select thread exit");
    select_thread->join();
    delete select_thread; select_thread = NULL;
}


