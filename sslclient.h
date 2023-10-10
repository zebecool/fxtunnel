#ifndef _FX_SSL_CLIENT_H__
#define _FX_SSL_CLIENT_H__

#include "sock.h"
#include "agent.h"
#include "connector.h"
#include "fxtunnel.h"

class sslclient : public fxtunnel
{
public:
	sslclient();
	~sslclient();
	virtual int _load_config(mjson& json_conf);
	virtual int _init();
	int _connect();
	int _read();
	int _write(const char* sbuf, int sbuf_len);
	void _close();
	int proc_auth(msg_auth* _msg);
	int proc_ping(msg_ping* _msg);
	int proc_forwarding(msg_forwarding* _msg);
	int process_message();
	void loop();
	virtual void _run();
	virtual void _stop();

	virtual std::string get_format_running_info();
	virtual void get_running_info(mjson& json_info);
public:
	SSL* ssl;
	int auth_state; // 0: init;  1: success;  2: auth failure;  3: kick out
	int network_delay;

	int sock;
	std::string server_addr;
	std::string server_ipaddr;
	int server_port;
	uint64_t token;
	std::string authkey;
	std::map<uint64_t, service_st*> service_map; //usid <---> service_st*
private:
	char* r_buf;
	int r_buf_size;
	int r_buf_pos;
	uint32_t r_time; //sock alive time
};

#endif

