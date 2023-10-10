#ifndef _FX_TUNNEL__H_
#define _FX_TUNNEL__H_


//----------------------------------------------------------
// ssl mgr
//----------------------------------------------------------

class sslmgr
{
public:
    sslmgr() { ctx_ = NULL; };
    ~sslmgr();
    int init() {
        // Initialize OpenSSL
        SSL_library_init();
        // Load Algorithm Library
        OpenSSL_add_all_algorithms();
        // Loading error handling information
        SSL_load_error_strings();
        return 0;
    };
    SSL_CTX* ctx() { return ctx_; }
    int init_server(std::string _cert_file, std::string _private_key_file) {
        cert_file = _cert_file;
        private_key_file = _private_key_file;

        // Select Session Protocol, There are multiple versions to choose from
        SSL_METHOD* method = (SSL_METHOD*)SSLv23_server_method();
        // Create Session Environment
        ctx_ = SSL_CTX_new(method);
        if (ctx_ == NULL) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
        //SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1);

        // Set certificate validation method
        SSL_CTX_set_security_level(ctx_, 0);
        // Load CA certificate for SSL session
        if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
        // Load private key for SSL session
        if (SSL_CTX_use_PrivateKey_file(ctx_, private_key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
        // Verify that the private key matches the certificate (actually the digital signature in the certificate)
        if (!SSL_CTX_check_private_key(ctx_)) {
            ERR_print_errors_fp(stdout);
            return -1;
        }
        return 0;
    };
    int destroy_server() {
        SSL_CTX_free(ctx_);
        return 0;
    };
    int init_client() {
        // Select Session Protocol
        SSL_METHOD* method = (SSL_METHOD*)SSLv23_client_method();
        // Create Session Environment
        ctx_ = SSL_CTX_new(method);
        if (ctx_ == NULL) {
            ERR_print_errors_fp(stdout);
            exit(1);
        }
        //SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1);
        return 0;
    };
    int destroy_client() {
        SSL_CTX_free(ctx_);
        return 0;
    };
    void certificate_info(SSL* _ssl) {
        X509* cert = SSL_get_peer_certificate(_ssl);
        if (cert != NULL) {
            logit("digital certificate information:");
            std::string line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            logit("    certificate:  %s", line.c_str());
            line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            logit("    Issuer:  %s", line.c_str());
            X509_free(cert);
        }
        else {
            logit("no certificate information.");
        }
    };
    SSL_CTX* ctx_;
    std::string cert_file;
    std::string private_key_file;
    SSL* ssl_c; //for client only
};


//----------------------------------------------------------
// fxtunnel class
//----------------------------------------------------------
enum {
    MODE_SERVER,
    MODE_CLIENT
};

class linkconfig
{
public:
    linkconfig() { connected = false; };
    std::string authkey;
    uint64_t token;
    bool connected;
    std::string ipaddr;
    int port;
    int network_delay;
    std::map<uint64_t, service_st*> service_map; //usid <---> service_st*
};

class agentmgr;
class connmgr;
class udpagentmgr;
class udpconnmgr;

class fxtunnel
{
public:
    fxtunnel();
    ~fxtunnel();
    void send_notify(queitem* _qitem) { pairfd->notify(_qitem); };
    void release_notify() { pairfd->release(); };
    virtual int  _load_config(mjson& json_conf) = 0;
    virtual int  _init() = 0;
    virtual void _run() = 0;
    virtual void _stop() = 0;
    virtual void get_running_info(mjson& json_info) = 0;
    virtual std::string get_format_running_info() = 0;
    int init(mjson& json_conf, bool _deamon = true);
    void run();
    void stop();
    void reload();
public:
    sslmgr* sslm;
    agentmgr* amgr;
    connmgr* cmgr;
    udpagentmgr* uamgr;
    udpconnmgr* ucmgr;
    bool exit;

    std::thread* main_thread;
    fxqueue* tx_que;
    pairsock* pairfd;
};


//load json config file
int load_config(const char* _config_filepath, mjson& _json_conf);

#ifdef __linux__

int xt_daemonize(const char* _dir = NULL);
int xt_read_pidfile();
void xt_write_pidfile();
void xt_check_pidfile();
void xt_remove_pidfile();
void xt_reload_process();
bool xt_check_process();
void xt_kill_process();

int xt_fifo_init(bool _mode);
int xt_fifo_read(bool _mode, char* _buf, int _buflen);
int xt_fifo_write(bool _mode, const char* _buf, int _buflen);
void xt_fifo_close(bool _mode);

#endif



#ifdef _WIN32
#define CF std::string("\r\n")
#else
#define CF std::string("\n")
#endif
#define INDENT std::string("    ")


#endif

