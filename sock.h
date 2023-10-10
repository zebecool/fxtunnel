#ifndef _FX_SOCK__H_
#define _FX_SOCK__H_


// message type
enum {
    MSG_T__AUTH = 0,  // Link auth
    MSG_T__PING,      // ping heartbeat
    MSG_T__FORWARD,   // forward data
}; // MSG_TYPE
static inline const char* TYPE_S(int type) {
    switch (type) {
        case MSG_T__AUTH: return "MSG_T__AUTH";
        case MSG_T__PING: return "MSG_T__PING";
        case MSG_T__FORWARD: return "MSG_T__FORWARD";
        default: return "UNKNOWN_TYPE";
    }
};

// forward message subtype
enum {
    MSG_SUB__EMPTY = 0,
    // forwarding - session control
    MSG_SUB__SESSION_CTRL,  // create session | close session
    // forwarding - data
    MSG_SUB__TCP_FORWARDING,
    MSG_SUB__UDP_FORWARDING
}; // MSG_SUBTYPE
static inline const char* SUBTYPE_S(int type) {
    switch (type) {
        case MSG_SUB__EMPTY: return "EMPTY";
        case MSG_SUB__SESSION_CTRL: return "MSG_SUB__SESSION_CTRL";
        case MSG_SUB__TCP_FORWARDING: return "MSG_SUB__TCP_FORWARDING";
        case MSG_SUB__UDP_FORWARDING: return "MSG_SUB__UDP_FORWARDING";
        default: return "UNKNOWN_SUBTYPE";
    }
};

// message cmd
enum {
    MSG_CMD__EMPTY = 0,
    // for session control
    MSG_CMD__TCP_CONNECT, //to cmgr
    MSG_CMD__TCP_AGT_CONNECT, //to amgr
    MSG_CMD__TCP_DISCONNECT, //to cmgr
    MSG_CMD__TCP_AGT_DISCONNECT, //to amgr
    MSG_CMD__UDP_CONNECT, //to ucmgr
    MSG_CMD__UDP_AGT_CONNECT, //to uamgr
    MSG_CMD__UDP_DISCONNECT, //to ucmgr
    MSG_CMD__UDP_AGT_DISCONNECT, //to uamgr
    // for forwarding
    MSG_CMD__FORWARDING,
    MSG_CMD__AGT_FORWARDING,
};
static inline const char* CMD_S(int type) {
    switch (type) {
        case MSG_CMD__EMPTY: return "/";
        case MSG_CMD__TCP_CONNECT: return "MSG_CMD__TCP_CONNECT";
        case MSG_CMD__TCP_AGT_CONNECT: return "MSG_CMD__TCP_AGT_CONNECT";
        case MSG_CMD__TCP_DISCONNECT: return "MSG_CMD__TCP_DISCONNECT";
        case MSG_CMD__TCP_AGT_DISCONNECT: return "MSG_CMD__TCP_AGT_DISCONNECT";
        case MSG_CMD__UDP_CONNECT: return "MSG_CMD__UDP_CONNECT";
        case MSG_CMD__UDP_AGT_CONNECT: return "MSG_CMD__UDP_AGT_CONNECT";
        case MSG_CMD__UDP_DISCONNECT: return "MSG_CMD__UDP_DISCONNECT";
        case MSG_CMD__UDP_AGT_DISCONNECT: return "MSG_CMD__UDP_AGT_DISCONNECT";
        case MSG_CMD__FORWARDING: return "MSG_CMD__FORWARDING";
        case MSG_CMD__AGT_FORWARDING: return "MSG_CMD__AGT_FORWARDING";
        default: return "UNKNOWN_CMD";
    }
};

enum {
    PROTOCOL_TCP_SC = 0,
    PROTOCOL_TCP_SA,
    PROTOCOL_UDP_SC,
    PROTOCOL_UDP_SA
};
static inline const char* PROTOCOL_S(int type) {
    switch (type) {
        case PROTOCOL_TCP_SC: return "TCP";
        case PROTOCOL_TCP_SA: return "TCP";
        case PROTOCOL_UDP_SC: return "UDP";
        case PROTOCOL_UDP_SA: return "UDP";
        default: return "unknown protocol";
    }
};
static inline const char* PROTOCOL_TIPS(int type, bool _server = true) {
    switch (type) {
    case PROTOCOL_TCP_SC: { if (_server) return "Connector";    else return "Agent listen"; }
    case PROTOCOL_TCP_SA: { if (_server) return "Agent listen"; else return "Connector"; }
    case PROTOCOL_UDP_SC: { if (_server) return "Connector";    else return "Agent listen"; }
    case PROTOCOL_UDP_SA: { if (_server) return "Agent listen"; else return "Connector"; }
    default: return "unknown protocol tips";
    }
};

#pragma pack (1)

typedef struct _msg_header
{
    uint32_t   length;
    uint32_t   when;
    uint64_t   token;
    uint8_t    type;        // MSG_TYPE
    int        status;      // PPF_STATUS_CODE
    uint64_t   usid;        // service Id
    uint64_t   seid;        // Session Id
    //char       data[];
} msg_header;
#define msg_h_len sizeof(msg_header)
#define msg_data(_msg_ptr) ((char*)_msg_ptr + msg_h_len)

typedef struct _service_st
{
    uint64_t   usid;
    char       name[64];
    int        protocol; // protocol enum
    int        mapped_port;
    char       connect_addr[64];
    char       connect_ipaddr[16];
    int        connect_port;
    int        status; // 0: no-active; 1: actived
    int        session_count; //connection count for statistics
} service_st;

typedef struct _msg_auth
{
    msg_header header;
    char       authkey[33];
    int        status; // auth status.  0: success   1: failure
    int        service_count;
    //service_st services[];
} msg_auth;

typedef struct _msg_ping
{
    msg_header header;
    int        delay_msecs; //last heartbeat network delay
    uint64_t   tx_msecs;
    uint64_t   rx_msecs;
    uint64_t   tx_rx_msecs;
} msg_ping;

typedef struct _msg_forwarding
{
    msg_header header;
    uint8_t    subtype;
    uint8_t    cmd;
    uint32_t   datalen;
    //char       data[];
} msg_forwarding;
#define msg_forwarding_len sizeof(msg_forwarding)
#define forwarding_msg(_msg_ptr) ((char*)_msg_ptr + sizeof(msg_forwarding))

#pragma pack ()


#define pack_msg(_msg,_len,_token,_type,_usid,_seid) \
    do { \
        msg_header* msg_h_ = (msg_header*)_msg; \
        msg_h_->length = _len; msg_h_->when = (unsigned int)time(0); \
        msg_h_->token = _token; msg_h_->type = _type; \
        msg_h_->usid = _usid; msg_h_->seid = _seid; \
    } while (0)

#define pack_forwarding(_msg_fw,_subtype,_cmd,_status) \
    do { \
        msg_fw->subtype = _subtype; msg_fw->cmd = _cmd; msg_fw->header.status = _status; \
    } while (0)



enum {
    Err__Success = 0,
    Err__Failure = 10001,
    Err__Exception,
    Err__AuthFailure,
    Err__NetworkException,
    Err__ConnectFail,
};


#define NET_TX (1)
#define NET_RX (2)

static inline void logmsg_s(int rxtx, msg_header* msg_h) {
    if (MSG_T__AUTH == msg_h->type) {
        //return;
        msg_auth* msg = (msg_auth*)msg_h;
        if (NET_TX == rxtx) {
            logt("Tx  %s message. length[ %u ] token[ %llu ] usid[ %llu ] seid[ %llu ] status[ %d ]", TYPE_S(msg_h->type), msg_h->length, msg_h->token, msg_h->usid, msg_h->seid, msg->status);
        } else {
            logt("Rx  %s message. length[ %u ] token[ %llu ] usid[ %llu ] seid[ %llu ] status[ %d ]", TYPE_S(msg_h->type), msg_h->length, msg_h->token, msg_h->usid, msg_h->seid, msg->status);
        }
    }
    /*
    else if (MSG_T__PING == msg_h->type) {
        msg_ping* msg = (msg_ping*)msg_h;
        if (NET_TX == rxtx) {
            logt("Tx  %s message", TYPE_S(msg_h->type));
        } else {
            logt("Rx  %s message. cost msecs[ %u ]", TYPE_S(msg_h->type), (uint32_t)(msg->rx_rx_msecs-msg->tx_msecs));
        }
    }
    */
    else if (MSG_T__FORWARD == msg_h->type) {
        //return;
        msg_forwarding* msg = (msg_forwarding*)msg_h;
        //if (msg->subtype != MSG_SUB__SESSION_CTRL) { return; }
        if (NET_TX == rxtx) {
            logt("Tx Forward -> subtype[ %s ] cmd[ %s ] length[ %u ] token[ %llu ] usid[ %llu ] seid[ %llu ] datalen[ %d ]", SUBTYPE_S(msg->subtype), CMD_S(msg->cmd), msg_h->length, msg_h->token, msg_h->usid, msg_h->seid, msg->datalen);
        } else {
            logt("Rx Forward -> subtype[ %s ] cmd[ %s ] length[ %u ] token[ %llu ] usid[ %llu ] seid[ %llu ] datalen[ %d ]", SUBTYPE_S(msg->subtype), CMD_S(msg->cmd), msg_h->length, msg_h->token, msg_h->usid, msg_h->seid, msg->datalen);
        }
    }
};



//----------------------------------------------------------
// socket base class
//----------------------------------------------------------
static inline void _close_socket(int _sock) {
#ifdef WIN32
    ::closesocket(_sock);
#else
    close(_sock);
#endif
};
static inline void _set_sock_nonblock(int _sock) {
    int ret = 0;
#ifdef WIN32
    //set no-block
    ULONG NonBlock = 1;
    ret = ioctlsocket(_sock, FIONBIO, &NonBlock); assert(ret != SOCKET_ERROR);
    //set TCP_NODELAY
    int on = 1;
    ret = setsockopt(_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(on)); assert(ret != SOCKET_ERROR);
    ret = setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&on, sizeof(on)); assert(ret != SOCKET_ERROR);
#else
    //set no-block
    int flags = 1;
    flags = fcntl(_sock, F_GETFL); flags |= O_NONBLOCK; fcntl(_sock, F_SETFL, flags);
    //set TCP_NODELAY
    flags = 1; ret = setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flags, sizeof(flags)); assert(ret == 0);
    //keepalive
    flags = 1; ret = setsockopt(_sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags)); assert(ret == 0);
#endif
};
static inline std::string get_ipaddr(std::string _addr) {
    unsigned long addr_ul = inet_addr(_addr.c_str());
    if (addr_ul == INADDR_NONE) {
        //domain name
        struct addrinfo hints; struct addrinfo *result;
        //Obtain address(es) matching host/port
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET; //IPv4
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ALL;
        hints.ai_protocol = IPPROTO_TCP;
        int s = ::getaddrinfo(_addr.c_str(), "", &hints, &result);
        if (s != 0) { syserr("::getaddrinfo( %s )",_addr.c_str()); return ""; }
        char buff[32] = { 0 };
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, buff, sizeof(buff));
        logit("Domain name( %s )  ->  %s", _addr.c_str(), buff);
        freeaddrinfo(result);
        return buff;
    }
    return _addr;
};

class fxsock
{
public:
    fxsock() {
        connected = false; sock = -1; last_update = 0; port = 0; listen_port = 0;
        r_buf_size = BUF_SIZE; r_buf = (char*)malloc(r_buf_size); r_buf_pos = 0;
    };
    virtual ~fxsock() {
        //logt("Destroy one Tcp Sock");
        free((void*)r_buf);
    };
    void _set_nonblock() {
        _set_sock_nonblock(sock);
    };
    int _connect(std::string _addr, int _port) {
        addr = _addr; port = _port;
        //strcpy(s_ip, _svr_ip); s_port = _svr_port;
        addr = _addr; port = _port;
        ipaddr = get_ipaddr(_addr);
        if  (ipaddr.length() == 0) { logw("config address[ %s ] error",_addr.c_str()); return -1; }
        sock = (int)::socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) { syserr("::socket()"); return -1; }
        struct sockaddr_in dest; ::memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET; dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(ipaddr.c_str());
        ::memset(&(dest.sin_zero), 0, sizeof(dest.sin_zero));
        int ret = ::connect(sock, (struct sockaddr*)&dest, sizeof(dest));
        if (ret != 0) { syserr("::connect()"); _close(); return -1; }
        _set_nonblock();
        connected = true; last_update = get_now(); r_buf_pos = 0;
        //logt("connect to server[ %s : %d ] success", ipaddr.c_str(), port);
        /*
        //get sock local information
        struct sockaddr_in client; memset(&client, 0, sizeof(client)); int client_addr_length = sizeof(client);
        getsockname(sock, (struct sockaddr*)&client, &client_addr_length);
        local_ip = inet_ntoa(client.sin_addr); local_port = ntohs(client.sin_port);
        logit("connect to server[ %s : %d ] success. local[ %s : %d ]", _svr_ip, _svr_port, local_ip.c_str(), local_port);
        */
        return 0;
    };
    int _connect_nonblk(std::string _addr, int _port) {
        addr = _addr; port = _port;
        ipaddr = get_ipaddr(_addr);
        if  (ipaddr.length() == 0) { logw("config address[ %s ] error",_addr.c_str()); return -1; }
        sock = (int)::socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) { syserr("::socket()"); return -1; }
        _set_nonblock();
        struct sockaddr_in dest; ::memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET; dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(ipaddr.c_str());
        ::memset(&(dest.sin_zero), 0, sizeof(dest.sin_zero));
        int ret = ::connect(sock, (struct sockaddr*)&dest, sizeof(dest));
#ifdef WIN32
        if (-1 == ret && (WSAEINPROGRESS != WSAGetLastError() && WSAEWOULDBLOCK != WSAGetLastError()))
#else
        if (-1 == ret && (EINPROGRESS != errno && EWOULDBLOCK != errno))
#endif
        {
            syserr("::connect()"); _close(); return -1;
        }
        last_update = get_now(); r_buf_pos = 0;
        return 0;
    };
    int _connect_ex(std::string _addr, int _port, int _timeout) {
        addr = _addr; port = _port;
        ipaddr = get_ipaddr(_addr);
        if  (ipaddr.length() == 0) { logw("config address[ %s ] error",_addr.c_str()); return -1; }
        sock = (int)::socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) { syserr("::socket()"); return -1; }
        _set_nonblock();
        struct sockaddr_in dest; ::memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET; dest.sin_port = htons(port);
        dest.sin_addr.s_addr = inet_addr(ipaddr.c_str());
        ::memset(&(dest.sin_zero), 0, sizeof(dest.sin_zero));
        int ret = ::connect(sock, (struct sockaddr*)&dest, sizeof(dest));
#ifdef WIN32
        if (-1 == ret && (WSAEINPROGRESS != WSAGetLastError() && WSAEWOULDBLOCK != WSAGetLastError()))
#else
        if (-1 == ret && (EINPROGRESS != errno && EWOULDBLOCK != errno))
#endif
        { syserr("::connect()"); _close(); return -1; }
        fd_set rfds, wfds; FD_ZERO(&rfds); FD_ZERO(&wfds); FD_SET(sock, &rfds); FD_SET(sock, &wfds); int max_fd = sock;
        struct timeval tv = { 0 }; tv.tv_sec = _timeout; tv.tv_usec = 0;
        ret = ::select(max_fd + 1, &rfds, &wfds, NULL, &tv);
        if (ret < 0) { syserr("::select()"); _close(); return -1; }
        if (ret == 0) { syserr("connect timeout"); _close(); return -1; }
        if (!FD_ISSET(sock, &rfds) && !FD_ISSET(sock, &wfds)) { syserr("connect exception, close it"); _close(); return -1; }
        else if (FD_ISSET(sock, &rfds) && FD_ISSET(sock, &wfds)) {
            int error; socklen_t optlen = sizeof(error);
            int flag = ::getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &optlen);
            if (flag == 0 && error == 0) { connected = true; }
            else { connected = false; syserr("connect exception, close it"); _close(); return -1; }
        }
        else if (!FD_ISSET(sock, &rfds) && FD_ISSET(sock, &wfds)) { connected = true; }
        else { connected = false; syserr("connect exception, close it"); _close(); return -1; }
        last_update = get_now(); r_buf_pos = 0;
        //logt("Connect to server[ %s : %d ] success", ipaddr.c_str(), port);
        /*
        //get sock local information
        struct sockaddr_in client; memset(&client, 0, sizeof(client)); int client_addr_length = sizeof(client);
        getsockname(sock, (struct sockaddr*)&client, &client_addr_length);
        local_ip = inet_ntoa(client.sin_addr); local_port = ntohs(client.sin_port);
        logit("connect to server[ %s : %d ] success. local[ %s : %d ]", _svr_ip, _svr_port, local_ip.c_str(), local_port);
        */
        return 0;
    };
    int _accept(int _sfd) {
        struct sockaddr_in client; ::memset(&client, 0, sizeof(client)); socklen_t client_addr_length = sizeof(client);
        sock = (int)accept(_sfd, (struct sockaddr*)&client, &client_addr_length);
        if (sock < 0) { syserr("::accept()"); return -1; }
        _set_nonblock();
        connected = true; last_update = get_now(); r_buf_pos = 0;
        ipaddr = inet_ntoa(client.sin_addr); port = client.sin_port;
        //logd("accept new connection[ %s : %d ]", ipaddr.c_str(), port);
        return 0;
    };
    int _init_server() {
        sock = (int)::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { syserr("::socket()"); return -1; }
#ifdef WIN32
        // set SO_REUSEADDR
        int optint = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optint, sizeof(optint));
        // set FIONBIO
        ULONG NonBlock = 1;
        ioctlsocket(sock, FIONBIO, &NonBlock);
        // set TCP_NODELAY & SO_KEEPALIVE
        optint = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&optint, sizeof(optint));
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&optint, sizeof(optint));
#else
        //set no-block
        int flags = 1; flags = fcntl(sock, F_GETFL); flags |= O_NONBLOCK; fcntl(sock, F_SETFL, flags);
        //set TCP_NODELAY
        flags = 1; setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flags, sizeof(flags));
        //keepalive
        flags = 1; setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
        //reuse
        flags = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
#endif
        struct sockaddr_in serveraddr; memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_port = htons(listen_port);
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        int ret = ::bind(sock, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
        if (ret < 0) { _close(); syserr("::bind() failed"); return -1; }
        ret = ::listen(sock, 5);
        if (ret == -1) { _close(); syserr("::listen() failed"); return -1; }
        //logd("agent[ %llu : %s : %llu ] running, listening on port %d", usid, name.c_str(), token, listen_port);
        return 0;
    };
    int _read() {
        if (!is_connected()) return -1;
        int rlen = ::recv(sock, r_buf + r_buf_pos, r_buf_size - r_buf_pos, 0);
        if (rlen < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) { return 0; }
#else
            if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) { return 0; }
#endif
            /* syserr("::recv()"); */ _close(); return -1;
        }
        else if (rlen == 0) { /* syserr("The peer has performed an orderly shutdown"); */ _close(); return -1; }
        else { r_buf_pos += rlen; }
        last_update = get_now();
        return rlen;
    };
    int _write(const char* s_buf, int s_buf_len) {
        if (!is_connected()) return -1;
        int nwritten = 0;
        while (nwritten < s_buf_len) {
            int slen = ::send(sock, s_buf + nwritten, s_buf_len - nwritten, 0);
            if (slen < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) { fx_sleep(1); continue; }
#else
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { fx_sleep(1); continue; }
#endif
                else { /* syserr("::send()"); */ _close(); return -1; }
            }
            else if (slen == 0) { break; }
            else { nwritten += slen; }
        }
        last_update = get_now();
        return 0;
    };
    void _close() {
        if (!is_connected()) return;
        connected = false; _close_socket(sock); sock = -1; r_buf_pos = 0; last_update = 0;
        logt("close one connection [ %s : %d ]", ipaddr.c_str(), port);
    };
    bool is_connected() { return connected; };
public:
    std::atomic<bool> connected;
    int    sock;
    char*  r_buf;
    int    r_buf_size;
    int    r_buf_pos;
    time_t last_update; //last receive data time
public:
    std::string addr;
    std::string ipaddr;
    int port;
    int listen_port;
};


class pairsock
{
public:
    pairsock(fxqueue* _que) {
        que = _que;
        int sfd = (int)::socket(AF_INET, SOCK_STREAM, 0); assert(sfd >= 0);
        sockaddr_in addr; socklen_t addrlen = sizeof(addr);
        ::memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int ret = ::bind(sfd, (sockaddr*)&addr, addrlen); assert(ret >= 0);
        ret = ::listen(sfd, 5); assert(ret >= 0);
        ret = getsockname(sfd, (sockaddr*)&addr, &addrlen); assert(ret >= 0);
        std::string _ip = inet_ntoa(addr.sin_addr); int _port = ntohs(addr.sin_port);
        tx_fd = (int)::socket(AF_INET, SOCK_STREAM, 0); assert(tx_fd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET; addr.sin_addr.s_addr = inet_addr(_ip.c_str()); addr.sin_port = htons(_port);
        ret = ::connect(tx_fd, (sockaddr*)&addr, sizeof(sockaddr)); fx_assert(ret == 0, "");
        memset(&addr, 0, sizeof(addr));
        rx_fd = ::accept(sfd, (struct sockaddr*)&addr, &addrlen); fx_assert(rx_fd >= 0, "");
        _close_socket(sfd);
    };
    ~pairsock() {
        _close_socket(rx_fd); _close_socket(tx_fd);
    };
    int notify(uint16_t _type, uint64_t _dest, void* _ptr, uint16_t _len) {
        queitem* qitem = new queitem(_type);
        qitem->u64_param = _dest; qitem->ptr = _ptr; qitem->i_param = _len;
        que->put(qitem);
        return ::send(tx_fd, "*", 1, 0);
    };
    int notify(queitem* _qitem) {
        que->put(_qitem);
        return ::send(tx_fd, "*", 1, 0);
    };
    int release() {
        return ::recv(rx_fd, rbuf, 256, 0);
    };
    int rx_fd;
    int tx_fd;
    char rbuf[256];
    fxqueue* que;
};




//----------------------------------------------------------
// udp socket base class
//----------------------------------------------------------

static inline void _set_udp_sock_nonblock(int _sock) {
#ifdef WIN32
    //set no-block
    ULONG NonBlock = 1;
    int ret = ioctlsocket(_sock, FIONBIO, &NonBlock); assert(ret != SOCKET_ERROR);
#else
    //set no-block
    int flags = 1;
    flags = fcntl(_sock, F_GETFL); flags |= O_NONBLOCK; fcntl(_sock, F_SETFL, flags);
#endif
};

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

class fxudpsock
{
public:
    fxudpsock() {
        connected = false; sock = -1; last_update = 0; port = 0;
        r_buf_size = BUF_SIZE; r_buf = (char*)malloc(r_buf_size);
    };
    virtual ~fxudpsock() {
        free((void*)r_buf);
    };
    void _set_nonblock() {
        _set_udp_sock_nonblock(sock);
    };
    int _init(const char* _ipaddr, int _port) {
        ipaddr = _ipaddr; port = _port;
        sock = (int)::socket(AF_INET, SOCK_DGRAM, 0); if (sock < 0) { _close(); syserr("::socket()"); return -1; }
        _set_nonblock();
        connected = true; last_update = time(0);
        return 0;
    };
    int _init_server() {
        sock = (int)::socket(AF_INET, SOCK_DGRAM, 0); if (sock < 0) { _close(); syserr("::socket()"); return -1; }
        _set_nonblock();
        sockaddr_in addr_in; ::memset(&addr_in, 0, sizeof(struct sockaddr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(listen_port); addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
        int ret = ::bind(sock, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in));
        if (ret < 0) { _close(); syserr("::bind()"); return -2; }
        connected = true; last_update = time(0);
        return 0;
    };
    int _read_buf(char* _ipaddr, int* _port) {
        int addr_in_len = sizeof(struct sockaddr_in);
        sockaddr_in addr_in; ::memset(&addr_in, 0, sizeof(struct sockaddr_in));
        int rlen = ::recvfrom(sock, r_buf, r_buf_size, 0, (sockaddr*)&addr_in, (socklen_t*)&addr_in_len);
        if (rlen == INVALID_SOCKET) { _close(); syserr("::recvfrom()"); return -1; }
        if (_ipaddr) { strcpy(_ipaddr, inet_ntoa(addr_in.sin_addr)); *_port = ntohs(addr_in.sin_port); }
        //logd("Udp recvfrom[ %s : %d ] data. len[ %d ]", _ipaddr, *_port, rlen);
        last_update = time(0);
        return rlen;
    };
    int _send_buf(const char* _ipaddr, int _port, const char* s_buf, int s_buf_len) {
        sockaddr_in addr_in; ::memset(&addr_in, 0, sizeof(struct sockaddr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = inet_addr(_ipaddr); addr_in.sin_port = htons(_port);
        int nwritten = 0;
        while (nwritten < s_buf_len) {
            int slen = ::sendto(sock, s_buf + nwritten, s_buf_len - nwritten, 0, (sockaddr*)&addr_in, sizeof(struct sockaddr_in));
            if (slen < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEINTR || WSAGetLastError() == WSAEWOULDBLOCK) { fx_sleep(1); continue; }
#else
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { fx_sleep(1); continue; }
#endif
                else { _close(); syserr("::sendto()"); return -1; }
            }
            else if (slen == 0) { break; }
            else {
                //logd("Udp sendto[ %s : %d ] data. len[ %d ]", _ipaddr, _port, slen);
                nwritten += slen;
            }
        }
        last_update = time(0);
        return 0;
    };
    int _send_buf_ex(const char* s_buf, int s_buf_len) {
        return _send_buf(ipaddr.c_str(), port, s_buf, s_buf_len);
    };
    void _close() {
        if (!is_connected()) return;
        connected = false; _close_socket(sock); sock = 0; last_update = 0;
        listen_port = 0;
    };
    bool is_connected() { return connected; };
public:
    std::atomic<bool> connected;
    int    sock;
    char*  r_buf;
    int    r_buf_size;
    time_t last_update; //last receive data time
public:
    std::string ipaddr;
    int port;
    int listen_port;
};


class pairudpsock
{
public:
    pairudpsock(fxqueue* _que) {
        que = _que;
        rx_fd = (int)::socket(AF_INET, SOCK_DGRAM, 0); assert(rx_fd >= 0);
        _set_udp_sock_nonblock(rx_fd);
        sockaddr_in name; ::memset(&name, 0, sizeof(name));
        name.sin_family = AF_INET;
        name.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t namelen = sizeof(name);
        int ret = ::bind(rx_fd, (sockaddr*)&name, namelen); assert(ret >= 0);
        ret = getsockname(rx_fd, (sockaddr*)&name, &namelen); assert(ret >= 0);
        std::string _ip = inet_ntoa(name.sin_addr); int _port = ntohs(name.sin_port);
        tx_fd = (int)::socket(AF_INET, SOCK_DGRAM, 0); assert(tx_fd >= 0);
        _set_udp_sock_nonblock(tx_fd);
        ipaddr = _ip; port = _port;
    };
    ~pairudpsock() {
        _close_socket(rx_fd); _close_socket(tx_fd);
    };
    int notify(queitem* _qitem) {
        que->put(_qitem);
        sockaddr_in addr_in; ::memset(&addr_in, 0, sizeof(struct sockaddr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_addr.s_addr = inet_addr(ipaddr.c_str()); addr_in.sin_port = htons(port);
        return ::sendto(tx_fd, "*", 1, 0, (sockaddr*)&addr_in, sizeof(struct sockaddr_in));
    };
    int release() {
        int addr_in_len = sizeof(struct sockaddr_in);
        sockaddr_in addr_in; ::memset(&addr_in, 0, sizeof(struct sockaddr_in));
        return ::recvfrom(rx_fd, rbuf, 256, 0, (sockaddr*)&addr_in, (socklen_t*)&addr_in_len);
    };
    int rx_fd;
    int tx_fd;
    std::string ipaddr;
    int port;
    char rbuf[256];
    fxqueue* que;
};


#endif
