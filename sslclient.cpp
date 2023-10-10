#include "typedef.h"
#include "sslclient.h"


sslclient::sslclient()
{
    sock = 0; auth_state = 0; network_delay = 0;
    r_buf_size = BUF_SIZE * 2; r_buf_pos = 0;
    r_buf = (char*)malloc(r_buf_size); assert(r_buf);
}
sslclient::~sslclient()
{
    sslm->destroy_client();
}

int sslclient::_load_config(mjson& json_conf)
{
    //load config file
    try {
        std::string server_addr_s = json_conf["server_addr"];
        server_addr = server_addr_s;
        server_port = json_conf["server_port"];
        std::string authkey_s = json_conf["authkey"];
        authkey = authkey_s;
    } catch (...) {
        logerr("Load configuration file failure");
        return -1;
    }
    logp("    server_addr: %s", server_addr.c_str());
    logp("    server_port: %d", server_port);
    logp("    authkey: %s", authkey.c_str());
    return 0;
}
int sslclient::_init()
{
    sslm = new sslmgr();
    int ret = sslm->init_client();
    if (ret < 0) {
        logerr("sslmgr init client failure");
        return -1;
    }
    amgr = new agentmgr(this); fx_assert(amgr,"");
    ret = amgr->init(); fx_assert(ret==0, "amgr init()");
    amgr->run();

    cmgr = new connmgr(this); assert(cmgr);
    ret = cmgr->init(); fx_assert(ret == 0, "cmgr init()");
    cmgr->run();

    uamgr = new udpagentmgr(this); fx_assert(uamgr, "");
    ret = uamgr->init(); fx_assert(ret == 0, "uamgr init()");
    uamgr->run();

    ucmgr = new udpconnmgr(this); assert(ucmgr);
    ret = ucmgr->init(); fx_assert(ret == 0, "ucmgr init()");
    ucmgr->run();
    return 0;
}
int sslclient::_connect()
{
    ssl = NULL; token = 0; auth_state = 0;

    server_ipaddr = get_ipaddr(server_addr);
    if (server_ipaddr.length() == 0) {
        logerr("connect address error. addr[ %s ]", server_addr.c_str());
        return -1;
    }

    sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if ((sock) < 0) {
        syserr("::socket()");
        return -1;
    }
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ipaddr.c_str(), (struct in_addr*)&dest.sin_addr.s_addr) == 0) {
        syserr("::inet_pton()");
        return -1;
    }
    int ret = ::connect(sock, (struct sockaddr*)&dest, sizeof(dest));
    if (ret != 0) {
        syserr("::connect()");
        return -1;
    }
    _set_sock_nonblock(sock);
    logit("socket connect %s : %d success.", server_ipaddr.c_str(), server_port);

    ssl = SSL_new(sslm->ctx());
    if (ssl == NULL) {
        syserr("::SSL_new()");
        return -1;
    }
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);
    while (-1 == SSL_connect(ssl)) {
        int sslerrno = SSL_get_error(ssl, -1);
        switch (sslerrno) {
            case SSL_ERROR_WANT_READ:  {
                //logt("SSL_connect() return, Wait for data to be read");
                break;
            }
            case SSL_ERROR_WANT_WRITE:  {
                //logt("SSL_connect() return, Wait for data to be write");
                break;
            }
            default: {
                char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
                std::string sslstate = SSL_state_string(ssl);
                logw("SSL_connect( %s : %d ) faliure. ssl_errno[ %d : %s : %s ]", server_ipaddr.c_str(), server_port, sslerrno, sslerrmsg, sslstate.c_str());
                return -1;
            }
        }
    }
    logit("ssl connect %s : %d success.", server_ipaddr.c_str(), server_port);
    r_time = get_now(); r_buf_pos = 0;

    // send auth message
    int mlen = sizeof(msg_auth);
    msg_auth* msg = (msg_auth*)malloc(mlen);
    memset((char*)msg, 0, mlen);
    pack_msg(msg, mlen, 0, MSG_T__AUTH, 0, 0);
    strncpy(msg->authkey, authkey.c_str(), 32);
    ret = _write((char*)msg, (int)msg->header.length);
    if (ret < 0) { free(msg); return -1; }
    logit("send auth message. token[ %llu ] authkey[ %s ]", token, msg->authkey);
    free(msg);
    return 0;
}
int sslclient::_read() {
    int rlen = SSL_read(ssl, r_buf + r_buf_pos, r_buf_size - r_buf_pos);
    if (rlen <= 0) {
        int sslerrno = SSL_get_error(ssl, rlen);
        if (rlen < 0) {
            int err = SSL_get_error(ssl, -1);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                //logt("SSL_read() return, Wait for data to be read or to be write");
                return 0;
            }
        }
        char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
        std::string sslstate = SSL_state_string(ssl);
        logerr("ssl read error. rlen[ %d ] ssl_errno[ %d : %s : %s ]", rlen, sslerrno, sslerrmsg, sslstate.c_str());
        return -1;
    }
    r_buf_pos += rlen;
    //logit("ssl read data length %d", rlen);
    return 0;
}
int sslclient::_write(const char* sbuf, int sbuf_len) {
    int slen = 0, pos = 0;
    while (pos < sbuf_len) {
        slen = SSL_write(ssl, sbuf, sbuf_len);
        if (slen <= 0) {
            int sslerrno = SSL_get_error(ssl, slen);
            if (slen < 0) {
                if (sslerrno == SSL_ERROR_WANT_READ || sslerrno == SSL_ERROR_WANT_WRITE) {
                    //logt("SSL_write() return, Wait for data to be read or to be write");
                    continue;
                }
            }
            char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
            std::string sslstate = SSL_state_string(ssl);
            logerr("ssl write error. slen[ %d ] ssl_errno[ %d : %s : %s ]", slen, sslerrno, sslerrmsg, sslstate.c_str());
            return -1;
        }
        pos += slen;
    }
    logmsg_s(NET_TX, (msg_header*)sbuf);
    return 0;
}
void sslclient::_close()
{
    _close_socket(sock);
    if (ssl) {
        //SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }
}
int sslclient::proc_auth(msg_auth* _msg)
{
    if (_msg->status == 1) {
        //auth success
        token = _msg->header.token;
        logit("client auth success. token[ %llu ]", token);
        //service list
        service_st* sts = (service_st*)((char*)_msg + sizeof(msg_auth));
        for (int i = 0; i < _msg->service_count; i++) {
            service_st* _sts = (service_st*)malloc_msg(sizeof(service_st));
            memcpy(_sts, (char*)sts, sizeof(service_st));
            service_map[_sts->usid] = _sts;
            sts += 1;
        }
        for (auto& iter : service_map) {
            sts = iter.second;
            if (sts->protocol == PROTOCOL_TCP_SC) {
                amgr->active_agent(token, sts->usid, sts->name, sts->mapped_port);
            } else if (sts->protocol == PROTOCOL_TCP_SA) {
                cmgr->active_conn(token, sts->usid, sts->name, sts->connect_addr, sts->connect_port);
            } else if (sts->protocol == PROTOCOL_UDP_SC) {
                uamgr->active_uagent(token, sts->usid, sts->name, sts->mapped_port);
            } else if (sts->protocol == PROTOCOL_UDP_SA) {
                ucmgr->active_uconn(token, sts->usid, sts->name, sts->connect_addr, sts->connect_port);
            }
        }
        auth_state = 1;
        return 0;
    }
    auth_state = _msg->status; // 0: init;  1: success;  2: auth failure;  3: kick out
    if (auth_state == 2) {
        //auth failure
        logerr("client auth failure. auth_key[ %s ]", _msg->authkey);
    } else if (auth_state == 3) {
        //kicked out by other devices
        logerr("client had kick out. auth_key[ %s ]", _msg->authkey);
    } else {
        logerr("client auth failure. unknown auth_state[ %d ]", auth_state);
    }
    fx_sleep(10 * 1000);
    return -1;
}
time_t last_print_ping_log_time = 0;
int sslclient::proc_ping(msg_ping* _msg)
{
    _msg->tx_rx_msecs = get_now_msecs();
    network_delay = (int)(_msg->tx_rx_msecs - _msg->tx_msecs); if (network_delay < 0) { network_delay = 0; }
    if (get_now() - last_print_ping_log_time > 60) {
        last_print_ping_log_time = get_now();
        logd("ping response message. network delay[ %d msecs ]", network_delay);
    }
    return 0;
}
int sslclient::proc_forwarding(msg_forwarding* _msg)
{
    if (_msg->subtype == MSG_SUB__SESSION_CTRL) {
        if (_msg->cmd == MSG_CMD__TCP_CONNECT) {
            cmgr->notify_create_session(_msg);
        } else if (_msg->cmd == MSG_CMD__TCP_AGT_CONNECT) {
            amgr->notify_session_connect(_msg);
        } else if (_msg->cmd == MSG_CMD__TCP_DISCONNECT) {
            cmgr->notify_session_disconnect(_msg);
        } else if (_msg->cmd == MSG_CMD__TCP_AGT_DISCONNECT) {
            amgr->notify_session_disconnect(_msg);
        } else if (_msg->cmd == MSG_CMD__UDP_CONNECT) {
            ucmgr->notify_create_session(_msg);
        } else if (_msg->cmd == MSG_CMD__UDP_AGT_CONNECT) {
            uamgr->notify_session_connect(_msg);
        } else if (_msg->cmd == MSG_CMD__UDP_DISCONNECT) {
            ucmgr->notify_session_disconnect(_msg);
        } else if (_msg->cmd == MSG_CMD__UDP_AGT_DISCONNECT) {
            uamgr->notify_session_disconnect(_msg);
        } else {
            fx_assert(false, "Unknown MSG_SUB__SESSION_CTRL cmd[ %u ]", _msg->cmd);
        }
    } else if (_msg->subtype == MSG_SUB__TCP_FORWARDING) {
        if (_msg->cmd == MSG_CMD__FORWARDING) {
            cmgr->notify_send_message(_msg);
        } else if (_msg->cmd == MSG_CMD__AGT_FORWARDING) {
            amgr->notify_send_message(_msg);
        } else {
            fx_assert(false, "Unknown MSG_SUB__TCP_FORWARDING cmd[ %u ]", _msg->cmd);
        }
    } else if (_msg->subtype == MSG_SUB__UDP_FORWARDING) {
        if (_msg->cmd == MSG_CMD__FORWARDING) {
            ucmgr->notify_send_message(_msg);
        } else if (_msg->cmd == MSG_CMD__AGT_FORWARDING) {
            uamgr->notify_send_message(_msg);
        } else {
            fx_assert(false, "Unknown MSG_SUB__UDP_FORWARDING cmd[ %u ]", _msg->cmd);
        }
    } else {
        fx_assert(false, "Unknown forwarding subtype[ %d ]", _msg->subtype);
    }
    return 0;
}
int sslclient::process_message()
{
    msg_header* msg_h = NULL;
    int start = 0; uint32_t left = r_buf_pos; char* buffer = r_buf;
    while (!exit) {
        if (left < msg_h_len) {
            if (0 != start && 0 != left) { memmove(buffer, buffer + start, left); }
            r_buf_pos = left;
            break;
        }
        msg_h = (msg_header*)(buffer + start);
        if (msg_h->length > left) {
            if (0 != start && 0 != left) { memmove(buffer, buffer + start, left); }
            r_buf_pos = left;
            break;
        }
        //has a complete message
        logmsg_s(NET_RX, msg_h);

        int ret = 0;
        switch (msg_h->type) {
            case MSG_T__AUTH:    { ret = proc_auth((msg_auth*)msg_h); break; }
            case MSG_T__PING:    { ret = proc_ping((msg_ping*)msg_h); break; }
            case MSG_T__FORWARD: { ret = proc_forwarding((msg_forwarding*)msg_h); break; }
            default: {
                logerr("Unknow message type[ %u : %s ]", msg_h->type, TYPE_S(msg_h->type));
                assert(false);
            }
        }
        if (ret < 0) { return -1; }
        start += msg_h->length; left -= msg_h->length;
    }
    return 0;
}
void sslclient::loop()
{
    int ret; int max_fd; fd_set rfds; uint32_t hb_time = get_now(); queitem* qitem;
    while (!exit) {
        uint32_t now = get_now();
        if (now - hb_time >= 7) {
            hb_time = now;
            //check auth
            if (auth_state != 1) {
                logw("auth failure, close socket. auth state[ %d ]", auth_state);
                break;
            } else if (now - r_time > 15) {
                logw("socket communication timeout, close socket");
                break;
            }
            // send heartbeat
            msg_ping msg; memset((char*)&msg, 0, sizeof(msg));
            pack_msg((&msg), sizeof(msg_ping), token, MSG_T__PING, 0, 0);
            msg.delay_msecs = network_delay;
            msg.tx_msecs = get_now_msecs();
            ret = _write((char*)&msg, (int)msg.header.length);
            if (ret < 0) { break; }
        }
        FD_ZERO(&rfds);
        FD_SET(pairfd->rx_fd, &rfds); max_fd = pairfd->rx_fd;
        FD_SET(sock, &rfds); if (sock > max_fd) max_fd = sock;
        struct timeval tv = { 0 }; tv.tv_sec = 0; tv.tv_usec = 50 * 1000;
        ret = ::select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) { syserr("::select()"); break; }
        else if (ret == 0) { continue; /* timeout */ }
        if (FD_ISSET(sock, &rfds)) {
            int rlen = _read(); if (rlen < 0) { break; }
            ret = process_message(); if (ret < 0) { break; }
            r_time = get_now();
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            release_notify();
            msg_header* msg_h = NULL; bool flag = false;
            while (!exit) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                msg_h = (msg_header*)qitem->ptr;
                ret = _write((char*)msg_h, (int)msg_h->length);
                if (ret < 0) { flag = true; break; }
                free(qitem->ptr); delete qitem;
            }
            if (flag) { break; }
        }
    }
    _close();
    auth_state = 0;
    for (auto& iter : service_map) {
        cmgr->destory_conn(iter.first);
        amgr->destory_agent(iter.first);
        delete iter.second;
    }
    fx_sleep(500);
    while (true) {
        qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
        free(qitem->ptr); delete qitem;
    }
    service_map.clear();
}
void sslclient::_run()
{
    int ret = 0;
    while (!exit) {
        ret = this->_connect();
        if (ret < 0) {
            logerr("sslclient connect failure");
            _close();
            fx_sleep(10 * 1000);
            continue;
        }
        this->loop();
    }
    sslm->destroy_client();
}
void sslclient::_stop() {
    exit = true;
    amgr->stop();
    cmgr->stop();
}
std::string sslclient::get_format_running_info()
{
    mjson json_info;
    get_running_info(json_info);
    std::string str;

    //refresh time
    char time_buf[64];
#ifdef WIN32
    SYSTEMTIME sys; GetLocalTime(&sys);
    sprintf(time_buf, "%4d-%02d-%02d %02d:%02d:%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
#else
    struct tm ptm; struct timeval tv; gettimeofday(&tv, NULL); localtime_r(&tv.tv_sec, &ptm);
    sprintf(time_buf, "%04d-%02d-%02d %02d:%02d:%02d", ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec);
#endif
    str += "Refresh Time  " + std::string(time_buf) + CF;
    str += CF;

    str += "Client Mode" + CF;
    if (server_addr != server_ipaddr && server_ipaddr.length() > 0) {
        str += "Server address ->  " + server_addr + " [" + server_ipaddr + "]" + CF;
    } else {
        str += "Server address ->  " + server_addr + CF;
    }
    str += "Server Listen Port ->  " + std::to_string(server_port) + CF;
    std::string state_s;
    if (auth_state == 0) {
        state_s = "connecting";
    } else if (auth_state == 1) {
        state_s = "connected";
    } else if (auth_state == 2) {
        state_s = "authentication failed";
    } else if (auth_state == 3) {
        state_s = "kicked out by other";
    } else  {
        state_s = "failure";
    }
    str += "state ->  " + state_s + CF;

    if (auth_state != 1) { str += CF; return str; }

    str += "Network Delay ->  " + std::to_string(network_delay) + " msecs" + CF;
    str += CF;

    str += "Services" + CF;
    for (int i=0;i<40;i++) { str = str + "-"; } str = str + CF; //separator line
    for (auto& iter : service_map) {
        service_st* sts = iter.second;
        sts->session_count = 0;
        if (sts->protocol == PROTOCOL_TCP_SC) {
            agent* agt = amgr->get_agent(sts->usid);
            if (agt) {
                sts->session_count = agt->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_TCP_SA) {
            conn* c = cmgr->get_conn(sts->usid);
            if (c) {
                strcpy(sts->connect_ipaddr, c->get_connect_ipaddr().c_str());
                sts->session_count = c->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_UDP_SC) {
            udpagent* uagt = uamgr->get_uagent(sts->usid);
            if (uagt) {
                sts->session_count = uagt->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_TCP_SA) {
            udpconn* uc = ucmgr->get_uconn(sts->usid);
            if (uc) {
                strcpy(sts->connect_ipaddr, uc->get_connect_ipaddr().c_str());
                sts->session_count = uc->get_session_count();
            }
        }
        str += sts->name + CF;

        std::string protocol_s, local_role, mapped_port_s;
        protocol_s = PROTOCOL_S(sts->protocol);
        local_role = PROTOCOL_TIPS(sts->protocol, false);
        if (PROTOCOL_TCP_SA == sts->protocol) {
            mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the server";
        } else if (PROTOCOL_TCP_SC == sts->protocol) {
            mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the local client";
        } else if (PROTOCOL_UDP_SA == sts->protocol) {
            mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the server";
        } else if (PROTOCOL_UDP_SC == sts->protocol) {
            mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the local client";
        }
        str += INDENT + "Mapped Port ->  " + mapped_port_s + CF;
        str += INDENT + "Protocol ->  " + protocol_s + CF;
        str += INDENT + "Local Role ->  " + local_role + CF;
        if (0 != strcmp(sts->connect_addr, sts->connect_ipaddr) && strlen(sts->connect_ipaddr) > 0) {
            str += INDENT + "Destnation address ->  " + std::string(sts->connect_addr) + " [" + sts->connect_ipaddr + "]" + CF;
        } else {
            str += INDENT + "Destnation address ->  " + std::string(sts->connect_addr) + CF;
        }
        str += INDENT + "Destnation Port ->  " + std::to_string(sts->connect_port) + CF;
        str += INDENT + "Session Count ->  " + std::to_string(sts->session_count) + CF;
        str += CF;
    }
    return str;
}
void sslclient::get_running_info(mjson& json_info)
{
    json_info["mode"] = "client";
    json_info["connect_addr"] = server_addr;
    json_info["connect_ipaddr"] = server_ipaddr;
    json_info["connect_port"] = server_port;
    json_info["state"] = auth_state;
    if (auth_state == 0) {
        json_info["authed_s"] = "connecting";
    } else if (auth_state == 1) {
        json_info["authed_s"] = "connected";
    } else if (auth_state == 2) {
        json_info["authed_s"] = "authentication failed";
    } else if (auth_state == 3) {
        json_info["authed_s"] = "kicked out by other";
    } else  {
        json_info["authed_s"] = "failure";
    }
    mjson json_services;
    for (auto& iter : service_map) {
        service_st* sts = iter.second;
        mjson json_svr;
        sts->session_count = 0;
        if (sts->protocol == PROTOCOL_TCP_SC) {
            agent* agt = amgr->get_agent(sts->usid);
            if (agt) {
                sts->session_count = agt->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_TCP_SA) {
            conn* c = cmgr->get_conn(sts->usid);
            if (c) {
                strcpy(sts->connect_ipaddr, c->get_connect_ipaddr().c_str());
                sts->session_count = c->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_UDP_SC) {
            udpagent* uagt = uamgr->get_uagent(sts->usid);
            if (uagt) {
                sts->session_count = uagt->get_session_count();
            }
        } else if (sts->protocol == PROTOCOL_TCP_SA) {
            udpconn* uc = ucmgr->get_uconn(sts->usid);
            if (uc) {
                strcpy(sts->connect_ipaddr, uc->get_connect_ipaddr().c_str());
                sts->session_count = uc->get_session_count();
            }
        }
        json_svr["name"] = sts->name;
        json_svr["protocol"] = sts->protocol;
        json_svr["protocol_s"] = PROTOCOL_S(sts->protocol);
        json_svr["protocol_role"] = PROTOCOL_TIPS(sts->protocol, false);
        json_svr["mapped_port"] = sts->mapped_port;
        json_svr["connect_addr"] = sts->connect_addr;
        json_svr["connect_ipaddr"] = sts->connect_ipaddr;
        json_svr["connect_port"] = sts->connect_port;
        json_svr["session_count"] = sts->session_count;
        json_services.push_back(json_svr);
    }
    json_info["services"] = json_services;
}
