#include "typedef.h"
#include "connector.h"
#include "fxtunnel.h"


connclt::connclt(uint64_t _seid, conn* _c)
{
    seid = _seid; c = _c;
}
connclt::~connclt()
{
}


conn::conn(uint64_t _token, uint64_t _usid, std::string _addr, int _port, std::string _name, connmgr* _cmgr)
{
    token = _token; usid = _usid; connect_addr = _addr; connect_port = _port; name = _name; cmgr = _cmgr;
}
conn::~conn()
{
    close_sessions();
}
int conn::init()
{
    connect_ipaddr = get_ipaddr(connect_addr);
    if  (connect_ipaddr.length() == 0) {
        logw("config address[ %s ] error",connect_addr.c_str());
        return -1;
    }
    return 0;
}
connclt* conn::get_connclt(uint64_t _seid)
{
    connclt* cclt = NULL;
    auto iter = connclt_map.find(_seid);
    if (iter != connclt_map.end()) {
        cclt = iter->second;
    }
    return cclt;
}
int conn::get_session_count()
{
    return connclt_map.size();
}
void conn::close_sessions()
{
    connclt* cclt = NULL;
    for (auto& iter : connclt_map) {
        cclt = iter.second;
        cclt->_close();
        delete cclt;
    }
    connclt_map.clear();
}
int conn::notify_connect_state(uint64_t _seid, int _cmd)
{
    queitem* qitem = new queitem();
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, _cmd, 0);
    qitem->ptr = msg_fw;
    cmgr->fxt->send_notify(qitem);
    return 0;
}


connmgr::connmgr(fxtunnel* _fxt)
{
	fxt = _fxt;
    connect_que = new fxqueue();
    tx_que = new fxqueue(); pairfd = new pairsock(tx_que);
}
connmgr::~connmgr()
{
    for (auto& iter : conn_map) {
        iter.second->close_sessions();
        delete iter.second;
    }
    conn_map.clear();
}
int connmgr::init()
{
	return 0;
}
conn* connmgr::get_conn(uint64_t _usid)
{
    conn* c = NULL;
    auto iter = conn_map.find(_usid);
    if (iter != conn_map.end()) {
        c = iter->second;
    }
    return c;
}
int connmgr::active_conn(uint64_t _token, uint64_t _usid, std::string _name, std::string _addr, int _port)
{
    conn* c = get_conn(_usid); if (c) { return 0; }
    c = new conn(_token, _usid, _addr, _port, _name, this); assert(c);
    if (c->init() < 0) { delete c; return -1; }
    queitem* qitem = new queitem(100);
    qitem->ptr = c;
    pairfd->notify(qitem);
    return 0;
}
void connmgr::destory_conn(uint64_t _usid)
{
    queitem* qitem = new queitem(101);
    qitem->usid = _usid;
    pairfd->notify(qitem);
}
void connmgr::notify_close_sessions(uint64_t _token)
{
    queitem* qitem = new queitem(102);
    qitem->token = _token;
    pairfd->notify(qitem);
}
void connmgr::notify_create_session(msg_forwarding* _msg)
{
    queitem* qitem = new queitem();
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    connect_que->put(qitem);
}
void connmgr::notify_session_disconnect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(104);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void connmgr::notify_send_message(msg_forwarding* _msg)
{
    queitem* qitem = new queitem();
    char* ptr = (char*)malloc(_msg->header.length); fx_assert(ptr,"malloc failed");
    ::memcpy(ptr, (char*)_msg, _msg->header.length);
    qitem->ptr = ptr;
    pairfd->notify(qitem);
}
int connmgr::connect_task()
{
    int ret = 0; int timeout = 1; connclt* cclt = NULL; queitem* qitem = NULL;
    std::map<uint64_t, connclt*> cclt_map; fd_set rfds, wfds;
    while (!exit) {
        qitem = (queitem*)connect_que->get(timeout);
        if (qitem) {
            uint64_t usid = qitem->usid; uint64_t seid = qitem->seid;
            delete qitem;
            conn* c = get_conn(usid);
            if (c) {
                //try connect
                cclt = new connclt(seid, c);
                ret = cclt->_connect_nonblk(c->connect_addr.c_str(), c->connect_port);
                if (ret < 0) {
                    logt("Connect server[ %s : %d ] failure. seid[ %llu ]", cclt->ipaddr.c_str(), cclt->port, cclt->seid);
                    c->notify_connect_state(cclt->seid, MSG_CMD__TCP_AGT_DISCONNECT);
                    delete cclt;
                } else {
                    cclt_map[cclt->seid] = cclt;
                }
            }
        }
        time_t t = get_now(); int max_fd = 0; int cnt = 0;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        for (auto iter = cclt_map.begin(); iter != cclt_map.end(); ) {
            cclt = iter->second;
            if (cclt->connected) {
                cclt_map.erase(iter++);
                logt("Connect to server[ %s : %d ] success. seid[ %llu ]", cclt->ipaddr.c_str(), cclt->port, cclt->seid);
                cclt->c->notify_connect_state(cclt->seid, MSG_CMD__TCP_AGT_CONNECT);
                queitem* qitem_c = new queitem(103);
                qitem_c->usid = cclt->c->usid; qitem_c->seid = cclt->seid; qitem_c->ptr = (void*)cclt;
                pairfd->notify(qitem_c);
                continue;
            }
            if (t - cclt->last_update > 5) {
                cclt_map.erase(iter++);
                logt("Connect server[ %s : %d ] failure. seid[ %llu ]", cclt->ipaddr.c_str(), cclt->port, cclt->seid);
                cclt->c->notify_connect_state(cclt->seid, MSG_CMD__TCP_AGT_DISCONNECT);
                delete cclt;
                continue;
            }
            FD_SET(cclt->sock, &rfds); FD_SET(cclt->sock, &wfds); if (cclt->sock > max_fd) max_fd = cclt->sock;
            cnt++;
            iter++;
        }
        if (cnt == 0) { timeout = 5; continue; } else { timeout = 1; }
        struct timeval tv = { 0 }; tv.tv_sec = 0; tv.tv_usec = 5 * 1000;
        ret = ::select(max_fd + 1, &rfds, &wfds, NULL, &tv);
        if (ret == 0) { continue; }
        else if (ret < 0) { syserr("::select()"); break; }
        for (auto& iter : cclt_map) {
            cclt = iter.second;
            if (FD_ISSET(cclt->sock, &rfds) && FD_ISSET(cclt->sock, &wfds)) {
                int error; socklen_t optlen = sizeof(error);
                int flag = ::getsockopt(cclt->sock, SOL_SOCKET, SO_ERROR, (char*)&error, &optlen);
                if (flag == 0 && error == 0) {
                    cclt->connected = true; cclt->last_update = get_now();
                } else {
                    cclt->connected = false; cclt->_close(); cclt->last_update = 0;
                }
            } else if (!FD_ISSET(cclt->sock, &rfds) && FD_ISSET(cclt->sock, &wfds)) {
                cclt->connected = true; cclt->last_update = get_now();
            } else {
                cclt->connected = false; cclt->_close(); cclt->last_update = 0;
            }
        }
    }
    //clean queue
    while (true) {
        queitem* qitem = (queitem*)connect_que->get(); if (qitem == NULL) break;
        delete qitem;
    }
    return 0;
}
void connmgr_connect_thread(connmgr* _cmgr)
{
    logd("start connmgr connect_task");
    _cmgr->connect_task();
    logd("exit connmgr connect_task");
}
int connmgr::select_task()
{
    int ret = 0; conn* c; connclt* cclt; int maxfd = 0; fd_set rfds; struct timeval tv;
    queitem* qitem; char* ptr; msg_forwarding* msg_fw; std::list<connclt*> coclt_list;
    while (!exit) {
        coclt_list.clear();
        FD_ZERO(&rfds);
        FD_SET(pairfd->rx_fd, &rfds); maxfd = pairfd->rx_fd;
        for (auto iter = conn_map.begin(); iter != conn_map.end();iter++) {
            c = iter->second;
            for (auto it = c->connclt_map.begin(); it != c->connclt_map.end();) {
                cclt = it->second;
                if (!cclt->is_connected()) {
                    c->connclt_map.erase(it++);
                    c->notify_connect_state(cclt->seid, MSG_CMD__TCP_AGT_DISCONNECT);
                    delete cclt;
                    continue;
                }
                FD_SET(cclt->sock, &rfds); if (cclt->sock > maxfd) maxfd = cclt->sock;
                coclt_list.push_back(cclt);
                it++;
            }
        }
        tv.tv_sec = 0; tv.tv_usec = 100 * 1000;
        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret == 0) { continue; }
        else if (ret < 0) { syserr("::select()"); break; }
        for (auto iter : coclt_list) {
            cclt = iter;
            if (FD_ISSET(cclt->sock, &rfds)) {
                ret = cclt->_read();
                if (ret > 0) {
                    int mlen = msg_forwarding_len + cclt->r_buf_pos;
                    msg_fw = (msg_forwarding*)malloc_msg(mlen);
                    pack_msg(msg_fw, mlen, cclt->c->token, MSG_T__FORWARD, cclt->c->usid, cclt->seid);
                    pack_forwarding(msg_fw, MSG_SUB__TCP_FORWARDING, MSG_CMD__AGT_FORWARDING, 0);
                    msg_fw->datalen = cclt->r_buf_pos;
                    memcpy(forwarding_msg(msg_fw), cclt->r_buf, msg_fw->datalen);
                    qitem = new queitem();
                    qitem->ptr = msg_fw;
                    fxt->send_notify(qitem);
                }
                cclt->r_buf_pos = 0;
            }
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            pairfd->release();
            while (true) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                if (qitem->type == 100) {
                    //add conn
                    c = (conn*)qitem->ptr;
                    conn_map[c->usid] = c;
                    logit("active conn.  usid[ %llu : %s ] addr[ %s : %d ] token[ %llu ]", c->usid, c->name.c_str(), c->connect_addr.c_str(), c->connect_port, c->token);
                }
                else if (qitem->type == 101) {
                    //delete conn
                    c = get_conn(qitem->usid);
                    if (c) {
                        c->close_sessions();
                        logit("destory conn. usid[ %llu : %s ] addr[ %s : %d ]", c->usid, c->name.c_str(), c->connect_addr.c_str(), c->connect_port);
                        delete c;
                        conn_map.erase(qitem->usid);
                    }
                }
                else if (qitem->type == 102) {
                    //close all sessions
                    for (auto& iter : conn_map) {
                        if (iter.second->token == qitem->token) {
                            iter.second->close_sessions();
                        }
                    }
                }
                else if (qitem->type == 103) {
                    //add new connection
                    c = get_conn(qitem->usid);
                    if (c) {
                        cclt = (connclt*)qitem->ptr;
                        c->connclt_map[cclt->seid] = cclt;
                    }
                }
                else if (qitem->type == 104) {
                    //process peer disconnect
                    c = get_conn(qitem->usid);
                    if (c) {
                        cclt = c->get_connclt(qitem->seid);
                        if (cclt) {
                            cclt->_close();
                        }
                    }
                }
                else if (qitem->type == 0) {
                    msg_fw = (msg_forwarding*)qitem->ptr;
                    ptr = forwarding_msg(msg_fw);
                    c = get_conn(msg_fw->header.usid);
                    if (c) {
                        cclt = c->get_connclt(msg_fw->header.seid);
                        if (cclt) {
                            cclt->_write(ptr, msg_fw->datalen);
                        } else {
                            c->notify_connect_state(msg_fw->header.seid, MSG_CMD__TCP_AGT_DISCONNECT);
                            logt("Not found connclt. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                        }
                    } else {
                        logw("Not found conn. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                    }
                    free(qitem->ptr);
                }
                else {
                    logw(" ConnMgr::select_task() Unknown queitem type[ %d ]", qitem->type);
                }
                delete qitem;
            }
        }
    }
    //close all session
    for (auto& iter : conn_map) {
        c = iter.second;
        for (auto& it : c->connclt_map) {
            it.second->_close();
            delete it.second;
        }
        c->connclt_map.clear();
        delete c;
    }
    conn_map.clear();
    //clean queue
    while (true) {
        queitem* qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
        free(qitem->ptr); delete qitem;
    }
    return 0;
}
void connmgr_select_thread(connmgr* _cmgr)
{
    logd("start connmgr select_task");
    _cmgr->select_task();
    logd("exit connmgr select_task");
}
void connmgr::run()
{
    exit = false;
    connect_thread = new std::thread(connmgr_connect_thread, this);
    select_thread = new std::thread(connmgr_select_thread, this);
}
void connmgr::stop()
{
    exit = true;
    logd("Wait connmgr connect_thread exit");
    connect_thread->join();
    delete connect_thread;
    connect_thread = NULL;
    logd("Wait connmgr select thread exit");
    select_thread->join();
    delete select_thread; select_thread = NULL;
}







udpconnclt::udpconnclt(uint64_t _seid, udpconn* _uc)
{
    seid = _seid; uc = _uc;
}
udpconnclt::~udpconnclt()
{
}


udpconn::udpconn(uint64_t _token, uint64_t _usid, std::string _addr, int _port, std::string _name, udpconnmgr* _ucmgr)
{
    token = _token; usid = _usid; connect_addr = _addr; connect_port = _port; name = _name; ucmgr = _ucmgr;
}
udpconn::~udpconn()
{
    close_sessions();
}
int udpconn::init()
{
    return 0;
}
udpconnclt* udpconn::get_uconnclt(uint64_t _seid)
{
    udpconnclt* ucclt = NULL;
    auto iter = uconnclt_map.find(_seid);
    if (iter != uconnclt_map.end()) {
        ucclt = iter->second;
    }
    return ucclt;
}
int udpconn::get_session_count()
{
    return uconnclt_map.size();
}
void udpconn::close_sessions()
{
    udpconnclt* ucclt = NULL;
    for (auto& iter : uconnclt_map) {
        ucclt = iter.second;
        ucclt->_close();
        delete ucclt;
    }
    uconnclt_map.clear();
}
int udpconn::notify_connect_state(uint64_t _seid, int _cmd)
{
    queitem* qitem = new queitem();
    msg_forwarding* msg_fw = (msg_forwarding*)malloc_msg(msg_forwarding_len);
    pack_msg(msg_fw, msg_forwarding_len, token, MSG_T__FORWARD, usid, _seid);
    pack_forwarding(msg_fw, MSG_SUB__SESSION_CTRL, _cmd, 0);
    qitem->ptr = msg_fw;
    ucmgr->fxt->send_notify(qitem);
    return 0;
}


udpconnmgr::udpconnmgr(fxtunnel* _fxt)
{
    fxt = _fxt;
    tx_que = new fxqueue(); pairfd = new pairudpsock(tx_que);
}
udpconnmgr::~udpconnmgr()
{
    for (auto& iter : uconn_map) {
        iter.second->close_sessions();
        delete iter.second;
    }
    uconn_map.clear();
}
int udpconnmgr::init()
{
    return 0;
}
udpconn* udpconnmgr::get_uconn(uint64_t _usid)
{
    udpconn* c = NULL;
    auto iter = uconn_map.find(_usid);
    if (iter != uconn_map.end()) {
        c = iter->second;
    }
    return c;
}
int udpconnmgr::active_uconn(uint64_t _token, uint64_t _usid, std::string _name, std::string _addr, int _port)
{
    udpconn* c = get_uconn(_usid); if (c) { return 0; }
    c = new udpconn(_token, _usid, _addr, _port, _name, this); assert(c);
    if (c->init() < 0) { delete c; return -1; }
    queitem* qitem = new queitem(100);
    qitem->ptr = c;
    pairfd->notify(qitem);
    return 0;
}
void udpconnmgr::destory_uconn(uint64_t _usid)
{
    queitem* qitem = new queitem(101);
    qitem->usid = _usid;
    pairfd->notify(qitem);
}

void udpconnmgr::notify_create_session(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(103);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void udpconnmgr::notify_session_disconnect(msg_forwarding* _msg)
{
    queitem* qitem = new queitem(104);
    qitem->token = _msg->header.token; qitem->usid = _msg->header.usid; qitem->seid = _msg->header.seid;
    pairfd->notify(qitem);
}
void udpconnmgr::notify_send_message(msg_forwarding* _msg)
{
    queitem* qitem = new queitem();
    char* ptr = (char*)malloc(_msg->header.length); fx_assert(ptr, "malloc failed");
    ::memcpy(ptr, (char*)_msg, _msg->header.length);
    qitem->ptr = ptr;
    pairfd->notify(qitem);
}
int udpconnmgr::select_task()
{
    int ret = 0; udpconn* uc; udpconnclt* ucclt; int maxfd = 0; fd_set rfds; struct timeval tv;
    queitem* qitem; char* ptr; msg_forwarding* msg_fw; std::list<udpconnclt*> ucoclt_list;
    while (!exit) {
        time_t t = get_now();
        ucoclt_list.clear();
        FD_ZERO(&rfds);
        FD_SET(pairfd->rx_fd, &rfds); maxfd = pairfd->rx_fd;
        for (auto iter = uconn_map.begin(); iter != uconn_map.end(); iter++) {
            uc = iter->second;
            for (auto it = uc->uconnclt_map.begin(); it != uc->uconnclt_map.end();) {
                ucclt = it->second;
                if (ucclt->is_connected() && t - ucclt->last_update > 120) { ucclt->_close(); }
                if (!ucclt->is_connected()) {
                    uc->uconnclt_map.erase(it++);
                    uc->notify_connect_state(ucclt->seid, MSG_CMD__UDP_AGT_DISCONNECT);
                    delete ucclt;
                    continue;
                }
                FD_SET(ucclt->sock, &rfds); if (ucclt->sock > maxfd) maxfd = ucclt->sock;
                ucoclt_list.push_back(ucclt);
                it++;
            }
        }
        tv.tv_sec = 0; tv.tv_usec = 100 * 1000;
        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret == 0) { continue; }
        else if (ret < 0) { syserr("::select()"); break; }
        for (auto iter : ucoclt_list) {
            ucclt = iter;
            if (FD_ISSET(ucclt->sock, &rfds)) {
                int rlen = ucclt->_read_buf(NULL, NULL);
                if (rlen > 0) {
                    int mlen = msg_forwarding_len + rlen;
                    msg_fw = (msg_forwarding*)malloc_msg(mlen);
                    pack_msg(msg_fw, mlen, ucclt->uc->token, MSG_T__FORWARD, ucclt->uc->usid, ucclt->seid);
                    pack_forwarding(msg_fw, MSG_SUB__UDP_FORWARDING, MSG_CMD__AGT_FORWARDING, 0);
                    msg_fw->datalen = rlen;
                    memcpy(forwarding_msg(msg_fw), ucclt->r_buf, msg_fw->datalen);
                    qitem = new queitem();
                    qitem->ptr = msg_fw;
                    fxt->send_notify(qitem);
                } else {
                    ucclt->_close();
                }
            }
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            pairfd->release();
            while (true) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                if (qitem->type == 100) {
                    //add udpconn
                    uc = (udpconn*)qitem->ptr;
                    uconn_map[uc->usid] = uc;
                    logit("active udpconn.  usid[ %llu : %s ] addr[ %s : %d ] token[ %llu ]", uc->usid, uc->name.c_str(), uc->connect_addr.c_str(), uc->connect_port, uc->token);
                }
                else if (qitem->type == 101) {
                    //delete udpconn
                    uc = get_uconn(qitem->usid);
                    if (uc) {
                        uc->close_sessions();
                        logit("destory udpconn. usid[ %llu : %s ] ipaddr[ %s : %d ]", uc->usid, uc->name.c_str(), uc->connect_addr.c_str(), uc->connect_port);
                        delete uc;
                        uconn_map.erase(qitem->usid);
                    }
                }
                else if (qitem->type == 102) {
                    //close_sessions
                    uc = get_uconn(qitem->usid);
                    if (uc) {
                        uc->close_sessions();
                    }
                }
                else if (qitem->type == 103) {
                    //add new connection
                    uc = get_uconn(qitem->usid);
                    if (uc) {
                        auto iter = uc->uconnclt_map.find(qitem->seid);
                        if (iter == uc->uconnclt_map.end()) {
                            ucclt = new udpconnclt(qitem->seid, uc);
                            ucclt->_init(uc->connect_ipaddr.c_str(), uc->connect_port);
                            uc->uconnclt_map[ucclt->seid] = ucclt;
                        } else {
                            ucclt = iter->second;
                        }
                        uc->notify_connect_state(ucclt->seid, MSG_CMD__UDP_AGT_CONNECT);
                    }
                }
                else if (qitem->type == 104) {
                    //process peer disconnect
                    uc = get_uconn(qitem->usid);
                    if (uc) {
                        ucclt = uc->get_uconnclt(qitem->seid);
                        if (ucclt) {
                            ucclt->_close();
                        }
                    }
                }
                else if (qitem->type == 0) {
                    msg_fw = (msg_forwarding*)qitem->ptr;
                    ptr = forwarding_msg(msg_fw);
                    uc = get_uconn(msg_fw->header.usid);
                    if (uc) {
                        ucclt = uc->get_uconnclt(msg_fw->header.seid);
                        if (ucclt) {
                            ucclt->_send_buf_ex(ptr, msg_fw->datalen);
                        } else {
                            uc->notify_connect_state(msg_fw->header.seid, MSG_CMD__UDP_AGT_DISCONNECT);
                            logd("Not found udpconnclt. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                        }
                    } else {
                        logd("Not found udpconn. token[ %llu ] usid[ %llu ] seid[ %llu ]", msg_fw->header.token, msg_fw->header.usid, msg_fw->header.seid);
                    }
                    free(qitem->ptr);
                } else {
                    logw(" udpconnmgr::select_task() Unknown queitem type[ %d ]", qitem->type);
                }
                delete qitem;
            }
        }
    }
    //close all session
    for (auto& iter : uconn_map) {
        uc = iter.second;
        for (auto& it : uc->uconnclt_map) {
            it.second->_close();
            delete it.second;
        }
        uc->uconnclt_map.clear();
        delete uc;
    }
    uconn_map.clear();
    //clean queue
    while (true) {
        queitem* qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
        free(qitem->ptr); delete qitem;
    }
    return 0;
}
void udpconnmgr_select_thread(udpconnmgr* _cmgr)
{
    logd("start udpconnmgr select_task");
    _cmgr->select_task();
    logd("exit udpconnmgr select_task");
}
void udpconnmgr::run()
{
    exit = false;
    select_thread = new std::thread(udpconnmgr_select_thread, this);
}
void udpconnmgr::stop()
{
    exit = true;
    logd("Wait udpconnmgr select thread exit");
    select_thread->join();
    delete select_thread; select_thread = NULL;
}


