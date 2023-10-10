#include "typedef.h"
#include "sslserver.h"


std::string SSL_CERT_FILE = "server.crt";
std::string SSL_KEY_FILE = "server.key";

sslconn::sslconn(uint64_t _token, int _cfd, SSL_CTX* _ctx)
{
    token = _token; sock = _cfd; ctx = _ctx; ssl = NULL; port = 0;
    destroy = false; ssl_accept = false; authed = false; linkcfg = NULL;
    r_buf_size = BUF_SIZE * 2; r_buf = (char*)malloc(r_buf_size); assert(r_buf); r_buf_pos = 0;
    last_update = 0;
}
sslconn::~sslconn() {
    if (r_buf) { free(r_buf); }
}
#if 0
int sslconn::_accept(char* _ipaddr, int _port)
{
    ipaddr = _ipaddr; port = _port;
    _set_sock_nonblock(sock);

    last_update = get_now();

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);

    while(true) {
        if (SSL_accept(ssl) != 1) {
            int sslerrno = SSL_get_error(ssl, -1);
            if ((sslerrno == SSL_ERROR_WANT_WRITE) || (sslerrno == SSL_ERROR_WANT_READ)) {
                char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
                std::string sslstate = SSL_state_string(ssl);
                logd("SSL_accept() return, Wait for data to be read. ssl_errno[ %d : %s : %s ]", sslerrno, sslerrmsg, sslstate.c_str());
                continue;
            }
            char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
            std::string sslstate = SSL_state_string(ssl);
            logerr("ssl accept error. ssl_errno[ %d : %s : %s ]", sslerrno, sslerrmsg, sslstate.c_str());
            _close();
            return -1;
        }
        //success
        ssl_accept = true;
        logit("accept new ssl connection. [ %s : %d ] token[ %llu ]", ipaddr.c_str(), port, token);
        break;
    }
    return 0;
}
#endif
int sslconn::init(char* _ipaddr, int _port) {
    ipaddr = _ipaddr; port = _port;
    _set_sock_nonblock(sock);

    last_update = get_now();

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_accept_state(ssl);

    int ret = _ssl_accept();
    if (ret < 0) {
        _close();
        return -1;
    } else if (ret > 0) {
        //Wait for data to be read
        return 0;
    }
    return 0;
}
int sslconn::_ssl_accept()
{
    int ret = SSL_accept(ssl);
    if (ret == 1) {
        //success
        ssl_accept = true;
        logit("accept new ssl connection. [ %s : %d ] token[ %llu ]", ipaddr.c_str(), port, token);
        return 0;
    }
    int sslerrno = SSL_get_error(ssl, -1);
    if (sslerrno == SSL_ERROR_WANT_READ || sslerrno == SSL_ERROR_WANT_WRITE) {
        char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
        std::string sslstate = SSL_state_string(ssl);
        //logt("SSL_accept() return, Wait for data to be read or to be write. ssl_errno[ %d : %s : %s ]", sslerrno, sslerrmsg, sslstate.c_str());
        return 1;
    }
    /*
    SSL_ERROR_SSL
    SSL_ERROR_SYSCALL
    SSL_ERROR_ZERO_RETURN
    SSL_ERROR_WANT_CONNECT
    */
    char sslerrmsg[1024] = { 0 }; ERR_error_string_n(ERR_get_error(), sslerrmsg, sizeof(sslerrmsg));
    std::string sslstate = SSL_state_string(ssl);
    logerr("ssl accept error. ssl_errno[ %d : %s : %s ]", sslerrno, sslerrmsg, sslstate.c_str());
    return -1;
}
int sslconn::_read()
{
    uint32_t mlen = *(uint32_t*)r_buf;
    //if message too long, relloc memory
    if (r_buf_pos > msg_h_len && mlen > r_buf_size) {
        if (mlen > BUF_SIZE) { _close(); return -1; }
        //realloc memmory
        r_buf_size = mlen;
        char* ptr = (char*)realloc(r_buf, r_buf_size); fx_assert(ptr != NULL, "realloc() error");
        r_buf = ptr;
    }
    int rlen = SSL_read(ssl, r_buf + r_buf_pos, r_buf_size - r_buf_pos);
    if (rlen <= 0) {
        if (rlen < 0) {
            int err = SSL_get_error(ssl, -1);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                //logt("SSL_read() return, Wait for data to be read or to be write");
                return 0;
            }
        }
        logerr("ssl read error. rlen[ %d ] error[ %d : %s ]", rlen, errno, strerror(errno));
        _close();
        return -1;
    }
    r_buf_pos += rlen;
    last_update = get_now();
    return 0;
}
int sslconn::_write(const char* sbuf, int sbuf_len)
{
    int slen = 0, pos = 0;
    while (pos < sbuf_len) {
        slen = SSL_write(ssl, sbuf, sbuf_len);
        if (slen <= 0) {
            if (slen < 0) {
                int err = SSL_get_error(ssl, -1);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    //logt("SSL_write() return, Wait for data to be read or to be write");
                    continue;
                }
            }
            logerr("ssl write error. ssl_errno[ %d ] error[ %d : %s ]", slen, errno, strerror(errno));
            _close();
            return -1;
        }
        pos += slen;
    }
    last_update = get_now();
    logmsg_s(NET_TX, (msg_header*)sbuf);
    return 0;
}
void sslconn::_close()
{
    if (!destroy) {
        destroy = true;
        if (linkcfg) {
            linkcfg->connected = false;
            linkcfg->ipaddr = "";
            linkcfg->port = 0;
            for (auto& iter : linkcfg->service_map) {
                iter.second->status = 0;
            }
        }
        if (ssl) { /* SSL_shutdown(ssl); */ SSL_free(ssl); ssl = NULL; }
        _close_socket(sock); sock = -1;
        logd("close one ssl connection [ %s : %d ]", ipaddr.c_str(), port);
    }
}



sslserver::sslserver()
{
    sock = 0; token_idx = 1;
}
sslserver::~sslserver() {
    //
}
int sslserver::_load_config(mjson& json_conf)
{
    //load config file
    try {
        listen_port = json_conf["listen_port"]; //服务监听端口
        //parse link config
        mjson json_links = json_conf["links"];
        for (mjson::iterator iter = json_links.begin(); iter != json_links.end(); ++iter) {
            mjson json_link = *iter;
            std::string authkey = json_link["authkey"];
            linkconfig* linkcfg = new linkconfig();
            linkcfg->authkey = authkey;
            linkcfg->token = 7000000 + token_idx++;
            mjson json_services = json_link["services"];
            for (mjson::iterator it = json_services.begin(); it != json_services.end(); ++it) {
                mjson json_service = *it;
                uint64_t usid = 700000000 + token_idx++;
                std::string name = json_service["name"];
                std::string protocol_s = json_service["protocol"];
                int protocol = 0;
                if (protocol_s == "tcp_sc") protocol = PROTOCOL_TCP_SC;
                else if (protocol_s == "tcp_sa") protocol = PROTOCOL_TCP_SA;
                else if (protocol_s == "udp_sc") protocol = PROTOCOL_UDP_SC;
                else if (protocol_s == "udp_sa") protocol = PROTOCOL_UDP_SA;
                else { throw -1; }
                int mapped_port = json_service["mapped_port"];
                std::string connect_addr = json_service["connect_addr"];
                int connect_port = json_service["connect_port"];

                service_st* sts = (service_st*)malloc_msg(sizeof(service_st));
                sts->usid = usid; strncpy(sts->name, name.c_str(), 63);
                sts->protocol = protocol; sts->mapped_port = mapped_port;
                strncpy(sts->connect_addr, connect_addr.c_str(), 63); sts->connect_port = connect_port;
                linkcfg->service_map[sts->usid] = sts;
            }
            link_config.push_back(linkcfg);
        }
    } catch (...) {
        logerr("Load configuration file failure");
        return -1;
    }
    logp("    listen_port: %d", listen_port);
    for (auto& iter : link_config) {
        logp("    link: %s", iter->authkey.c_str());
        for (auto& it : iter->service_map) {
            service_st* sts = it.second;
            logp("        service usid: %lu", (unsigned long)sts->usid);
            logp("            name: %s", sts->name);
            logp("            protocol: %s", PROTOCOL_S(sts->protocol));
            logp("            local role: %s", PROTOCOL_TIPS(sts->protocol));
            logp("            mapped port: %d", sts->mapped_port);
            logp("            connect_addr: %s", sts->connect_addr);
            logp("            connect_port: %d", sts->connect_port);
        }
    }
    return 0;
}
int sslserver::_init()
{
    sslm = new sslmgr();
    int ret = sslm->init_server(SSL_CERT_FILE, SSL_KEY_FILE);
    if (ret < 0) { logerr("sslmgr init server failure"); return -1; }

    amgr = new agentmgr(this); fx_assert(amgr, "");
    ret = amgr->init(); fx_assert(ret == 0, "amgr init()");
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

    // init services
    for (auto& iter : link_config) {
        linkconfig* linkcfg = iter;
        for (auto& it : iter->service_map) {
            service_st* sts = it.second;
            if (sts->protocol == PROTOCOL_TCP_SC) {
                cmgr->active_conn(linkcfg->token, sts->usid, sts->name, sts->connect_addr, sts->connect_port);
            } else if (sts->protocol == PROTOCOL_TCP_SA) {
                amgr->active_agent(linkcfg->token, sts->usid, sts->name, sts->mapped_port);
            } else if (sts->protocol == PROTOCOL_UDP_SC) {
                ucmgr->active_uconn(linkcfg->token, sts->usid, sts->name, sts->connect_addr, sts->connect_port);
            } else if (sts->protocol == PROTOCOL_UDP_SA) {
                uamgr->active_uagent(linkcfg->token, sts->usid, sts->name, sts->mapped_port);
            }
        }
    }

    ret = init_socket();
    if (ret < 0) {
        logerr("sslserver init faliure");
        return -1;
    }
    return 0;
}
int sslserver::init_socket()
{
    int ret = 0;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if ((sock) < 0) { syserr("::socket()"); return -1; }
#ifdef WIN32
    // set SO_REUSEADDR
    int optint = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optint, sizeof(optint)); assert(ret != SOCKET_ERROR);
#else
    //reuse
    int flags = 1; ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)); assert(ret == 0);
#endif
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(listen_port);
    saddr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr));
    if (ret == -1) { syserr("::bind()"); _close_socket(sock); return -1; }
    ret = listen(sock, 18);
    if (ret == -1) { syserr("::listen()");  _close_socket(sock); return -1; }
    logit("ssl server start. listen port %d", listen_port);
    return 0;
}
int sslserver::proc_auth(sslconn* _conn, msg_auth* _msg)
{
    _msg->header.when = get_now();
    _msg->header.token = 0;
    _msg->status = 2; //failure 
    std::string authkey = _msg->authkey;
    for (auto& iter : link_config) {
        linkconfig* linkcfg = iter;
        if (authkey == linkcfg->authkey) {
            auto it = sslconn_map.find(linkcfg->token);
            if (it == sslconn_map.end()) {
                uint64_t tmp_token = _conn->token;
                _conn->authed = true;
                _conn->token = linkcfg->token;
                linkcfg->ipaddr = _conn->ipaddr;
                linkcfg->port = _conn->port;
                linkcfg->connected = true;
                _conn->linkcfg = linkcfg;
                for (auto& iter : _conn->linkcfg->service_map) {
                    iter.second->status = 1;
                }

                queitem* qitem = new queitem(100);
                qitem->u64_param = tmp_token; qitem->ptr = _conn;
                tx_que->put(qitem);

                // auth success
                int mlen = sizeof(msg_auth) + _conn->linkcfg->service_map.size() * sizeof(service_st);
                msg_auth* msg = (msg_auth*)malloc_msg(mlen);
                pack_msg(msg, mlen, _conn->token, MSG_T__AUTH, 0, 0);
                msg->status = 1; //success
                msg->service_count = _conn->linkcfg->service_map.size();
                char* ptr = (char*)msg + sizeof(msg_auth);
                for (auto& iter : _conn->linkcfg->service_map) {
                    memcpy(ptr, (char*)iter.second, sizeof(service_st));
                    ptr += sizeof(service_st);
                }
                _conn->_write((char*)msg, msg->header.length);
                free(msg);
                logd("client[ %s : %d ] auth connection success. token[ %llu ]", _conn->ipaddr.c_str(), _conn->port, _conn->token);
                return 0;
            } else {
                //Close the current connection
                _msg->status = 3; //kick out
                logd("client[ %s : %d ] auth connection success, But keep previous connection, Close the current connection", _conn->ipaddr.c_str(), _conn->port);
            }
        }
    }
    if (_msg->status == 2) {
        logd("client[ %s : %d ] auth failure. authkey[ %s ]", _conn->ipaddr.c_str(), _conn->port, _msg->authkey);
    }
    _conn->_write((char*)_msg, _msg->header.length);
    _conn->_close();
    return 0;
}
int sslserver::proc_ping(sslconn* _conn, msg_ping* _msg)
{
    if (_conn->linkcfg) {
        _conn->linkcfg->network_delay = _msg->delay_msecs;
    }
    _msg->header.when = get_now();
    _msg->rx_msecs = get_now_msecs();
    return _conn->_write((char*)_msg, _msg->header.length);
}
int sslserver::proc_forwarding(sslconn* _conn, msg_forwarding* _msg)
{
    switch (_msg->subtype) {
        case MSG_SUB__SESSION_CTRL: {
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
            } else { fx_assert(false, "Unknown MSG_SUB__SESSION_CTRL cmd[ %u ]", _msg->cmd); }
            break;
        }
        case MSG_SUB__TCP_FORWARDING: {
            if (_msg->cmd == MSG_CMD__FORWARDING) {
                cmgr->notify_send_message(_msg);
            } else if (_msg->cmd == MSG_CMD__AGT_FORWARDING) {
                amgr->notify_send_message(_msg);
            } else { fx_assert(false, "Unknown MSG_SUB__TCP_FORWARDING cmd[ %u ]", _msg->cmd); }
            break;
        }
        case MSG_SUB__UDP_FORWARDING: {
            if (_msg->cmd == MSG_CMD__FORWARDING) {
                ucmgr->notify_send_message(_msg);
            } else if (_msg->cmd == MSG_CMD__AGT_FORWARDING) {
                uamgr->notify_send_message(_msg);
            } else { fx_assert(false, "Unknown MSG_SUB__UDP_FORWARDING cmd[ %u ]", _msg->cmd); }
            break;
        }
        default: {
            fx_assert(false, "Unknown subtype[ %d ]", _msg->subtype);
        }
    }
    return 0;
}
int sslserver::process_message(sslconn* _conn)
{
    msg_header* msg_h = NULL;
    int start = 0; uint32_t left = _conn->r_buf_pos; char* buffer = _conn->r_buf;
    while (true) {
        if (left < msg_h_len) {
            if (0 != start && 0 != left) { memmove(buffer, buffer + start, left); }
            _conn->r_buf_pos = left;
            break;
        }
        msg_h = (msg_header*)(buffer + start);
        if (msg_h->length > left) {
            if (0 != start && 0 != left) { memmove(buffer, buffer + start, left); }
            _conn->r_buf_pos = left;
            break;
        }
        //has a complete message
        logmsg_s(NET_RX, msg_h);

        if (!_conn->authed && msg_h->type != MSG_T__AUTH) {
            logerr("sslconn[ %s : %d ] not auth. close it", _conn->ipaddr.c_str(), _conn->port);
            return -1;
        }

        switch (msg_h->type) {
            case MSG_T__AUTH:    { proc_auth(_conn, (msg_auth*)msg_h); break; }
            case MSG_T__PING:    { proc_ping(_conn, (msg_ping*)msg_h); break; }
            case MSG_T__FORWARD: { proc_forwarding(_conn, (msg_forwarding*)msg_h); break; }
            default: {
                logerr("Unknow message type[ %u : %s ]", msg_h->type, TYPE_S(msg_h->type));
                return -1;
            }
        }
        start += msg_h->length; left -= msg_h->length;
    }
    return 0;
}
void sslserver::_run()
{
    int ret; int max_fd; fd_set rfds;
    sslconn* conn; queitem* qitem; msg_header* msg_h; msg_forwarding* msg_fw;
    while (!exit) {
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds); max_fd = sock;
        FD_SET(pairfd->rx_fd, &rfds); if (pairfd->rx_fd > max_fd) max_fd = pairfd->rx_fd;
        uint32_t now = get_now();
        for (auto iter = sslconn_map.begin(); iter != sslconn_map.end();) {
            uint64_t token = iter->first;
            conn = iter->second;
            if (conn->destroy || (((!conn->ssl_accept || !conn->authed) && now - conn->last_update > 3) || (now - conn->last_update > 15))) {
                amgr->notify_close_sessions(token);
                cmgr->notify_close_sessions(token);
                conn->_close(); delete conn;
                sslconn_map.erase(iter++);
                continue;
            }
            FD_SET(conn->sock, &rfds); if (conn->sock > max_fd) { max_fd = conn->sock; }
            iter++;
        }
        struct timeval tv = { 0 }; tv.tv_sec = 0; tv.tv_usec = 50 * 1000;
        ret = ::select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) { syserr("::select()"); break; }
        else if (ret == 0) { continue; /* Timeout */ }
        if (FD_ISSET(sock, &rfds)) {
            // accept connection
            struct sockaddr_in client; ::memset(&client, 0, sizeof(client)); socklen_t client_addr_length = sizeof(client);
            int sock_c = (int)accept(sock, (struct sockaddr*)&client, &client_addr_length);
            if (sock_c < 0) { syserr("::accept()"); return; }
            logit("accept new client connection. [ %s : %d ]", inet_ntoa(client.sin_addr), client.sin_port);
            conn = new sslconn(token_idx++, sock_c, sslm->ctx());
            ret = conn->init(inet_ntoa(client.sin_addr), client.sin_port);
            if (ret < 0) { delete conn; conn = NULL; continue; }
            sslconn_map[conn->token] = conn;
            if (token_idx >= 99999) token_idx = 1;
        }
        for (auto& iter : sslconn_map) {
            conn = iter.second;
            if (conn->destroy) { continue; }
            if (FD_ISSET(conn->sock, &rfds)) {
                if (!conn->ssl_accept) {
                    //logt("ssl accept second");
                    ret = conn->_ssl_accept(); if (ret < 0) { conn->_close(); continue; }
                } else {
                    ret = conn->_read(); if (ret < 0) { conn->_close(); continue; }
                    ret = process_message(conn); if (ret < 0) { conn->_close(); continue; }
                }
            }
        }
        if (FD_ISSET(pairfd->rx_fd, &rfds)) {
            release_notify();
            while (true) {
                qitem = (queitem*)tx_que->get(); if (qitem == NULL) break;
                if (qitem->type == 0) {
                    msg_h = (msg_header*)qitem->ptr;
                    auto iter = sslconn_map.find(msg_h->token);
                    if (iter != sslconn_map.end()) {
                        conn = iter->second;
                        if (!conn->destroy) {
                            conn->_write((char*)msg_h, msg_h->length);
                        }
                    } else {
                        //链路没有连接
                        if (msg_h->type == MSG_T__FORWARD) {
                            msg_fw = (msg_forwarding*)msg_h;
                            if (msg_fw->cmd == MSG_CMD__TCP_CONNECT) {
                                amgr->notify_session_disconnect(msg_fw);
                            } else if (msg_fw->cmd == MSG_CMD__UDP_CONNECT) {
                                uamgr->notify_session_disconnect(msg_fw);
                            }
                        }
                    }
                    free(qitem->ptr);
                } else if (qitem->type == 100) {
                    uint64_t tmp_token = qitem->u64_param;
                    sslconn_map.erase(tmp_token);
                    conn = (sslconn*)qitem->ptr;
                    sslconn_map[conn->token] = conn;
                }
                delete qitem;
            }
        }
    }
    _close_socket(sock);
    sslm->destroy_server();
    return;
}
void sslserver::_stop()
{
    exit = true;
    amgr->stop();
    cmgr->stop();
}
std::string sslserver::get_format_running_info()
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

    str += "Server Mode" + CF;
    str += "Listen Port ->  " + std::to_string(listen_port) + CF;
    int link_count = sslconn_map.size();
    str += "Number of connected links ->  " + std::to_string(link_count) + CF;
    str += CF;

    str = str + "Links" + CF;
    for (int i=0;i<40;i++) { str = str + "-"; } str = str + CF; //separator line
    for (auto& iter : link_config) {
        linkconfig* linkcfg = iter;
        str += "Client AuthKey ->  " + linkcfg->authkey + CF;
        str += INDENT + std::string("status ->  ") + (linkcfg->connected?"connected":"disconnect") + CF;
        if (linkcfg->connected) {
            str += INDENT + "ipaddr ->  " + linkcfg->ipaddr + CF;
            str += INDENT + "port ->  " + std::to_string(linkcfg->port) + CF;
            str += INDENT + "network delay ->  " + std::to_string(linkcfg->network_delay) + " msecs" + CF;
            str += INDENT + "token ->  " + std::to_string(linkcfg->token) + CF;
        }
        str += INDENT + "Services" + CF;
        str += INDENT;
        for (int i=0;i<40;i++) { str = str + "-"; } str = str + CF; //separator line
        for (auto& it : linkcfg->service_map) {
            service_st* sts = it.second;
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
            str += INDENT + sts->name + CF;

            std::string protocol_s, local_role, mapped_port_s;
            if (PROTOCOL_TCP_SA == sts->protocol) {
                protocol_s = "TCP";
                local_role = "agent listener";
                mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the local server";
            } else if (PROTOCOL_TCP_SC == sts->protocol) {
                protocol_s = "TCP";
                local_role = "connector";
                mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the client";
            } else if (PROTOCOL_UDP_SA == sts->protocol) {
                protocol_s = "UDP";
                local_role = "agent listener";
                mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the local server";
            } else if (PROTOCOL_UDP_SC == sts->protocol) {
                protocol_s = "UDP";
                local_role = "connector";
                mapped_port_s = "Listening on the port " + std::to_string(sts->mapped_port) + " on the client";
            }
            str += INDENT + INDENT + "Mapped Port ->  " + mapped_port_s + CF;
            str += INDENT + INDENT + "Protocol ->  " + protocol_s + CF;
            str += INDENT + INDENT + "Local Role ->  " + local_role + CF;
            if (0 != strcmp(sts->connect_addr, sts->connect_ipaddr) && strlen(sts->connect_ipaddr) > 0) {
                str += INDENT + INDENT + "Destnation address ->  " + std::string(sts->connect_addr) + " [" + sts->connect_ipaddr + "]" + CF;
            } else {
                str += INDENT + INDENT + "Destnation address ->  " + std::string(sts->connect_addr) + CF;
            }
            str += INDENT + INDENT + "Destnation Port ->  " + std::to_string(sts->connect_port) + CF;
            str += INDENT + INDENT + "Session Count ->  " + std::to_string(sts->session_count) + CF;
            str += CF;
        }
    }
    return str;
}
void sslserver::get_running_info(mjson& json_info)
{
    json_info["mode"] = "server";
    json_info["listen_port"] = listen_port;
    json_info["link_count"] = sslconn_map.size();
    mjson json_links;
    for (auto& iter : link_config) {
        linkconfig* linkcfg = iter;
        mjson json_link;
        json_link["token"] = linkcfg->token;
        json_link["authkey"] = linkcfg->authkey;
        json_link["connected"] = linkcfg->connected;
        json_link["ipaddr"] = linkcfg->ipaddr;
        json_link["port"] = linkcfg->port;
        json_link["network_delay"] = linkcfg->network_delay;
        mjson json_services;
        for (auto& it : linkcfg->service_map) {
            service_st* sts = it.second;
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
            json_svr["mapped_port"] = sts->mapped_port;
            json_svr["connect_addr"] = sts->connect_addr;
            json_svr["connect_ipaddr"] = sts->connect_ipaddr;
            json_svr["connect_port"] = sts->connect_port;
            json_svr["session_count"] = sts->session_count;
            json_services.push_back(json_svr);
        }
        json_link["services"] = json_services;
        json_links.push_back(json_link);
    }
    json_info["links"] = json_links;
}

