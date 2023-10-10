#ifndef _FX_SSL_SERVER__H_
#define _FX_SSL_SERVER__H_

#include "sock.h"
#include "agent.h"
#include "connector.h"
#include "fxtunnel.h"

//----------------------------------------------------------
// ssl connection
//----------------------------------------------------------
class sslconn
{
public:
	sslconn(uint64_t _token, int _cfd, SSL_CTX* _ctx);
	~sslconn();
	int init(char* _ipaddr, int _port);
	int _ssl_accept();
	int _read();
	int _write(const char* sbuf, int sbuf_len);
	void _close();
public:
	bool destroy;
	bool ssl_accept;
	bool authed;
	uint64_t token;
	int sock;
	std::string ipaddr;
	int port;
	SSL* ssl;
	SSL_CTX* ctx;
	linkconfig* linkcfg;

	char* r_buf;
	uint32_t r_buf_size;
	uint32_t r_buf_pos;
	uint32_t last_update;
};


//----------------------------------------------------------
// ssl server class
//----------------------------------------------------------
class sslserver : public fxtunnel
{
public:
	sslserver();
	~sslserver();
	virtual int _load_config(mjson& json_conf);
	virtual int _init();
	int init_socket();
	int proc_auth(sslconn* _conn, msg_auth* _msg);
	int proc_ping(sslconn* _conn, msg_ping* _msg);
	int proc_forwarding(sslconn* _conn, msg_forwarding* _msg);
	int process_message(sslconn* _conn);	
	int server_loop();
	virtual void _run();
	virtual void _stop();

	virtual void get_running_info(mjson& json_info);
	virtual std::string get_format_running_info();
public:
	sslmgr* sslm;
	agentmgr* amgr;
	connmgr* cmgr;
	
	int sock;
	int listen_port;
	uint64_t token_idx;

	std::thread* loop_thread;
private:
	std::map<uint64_t, sslconn*> sslconn_map;  // token <---> sslconn
	std::list<linkconfig*> link_config;
};


#endif

