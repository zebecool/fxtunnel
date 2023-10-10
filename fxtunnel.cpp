#include "typedef.h"
#include "sslclient.h"
#include "sslserver.h"
#include "fxtunnel.h"


extern int run_mode;

//----------------------------------------------------------
// fxtunnel class
//----------------------------------------------------------

fxtunnel::fxtunnel()
{
    sslm = NULL; exit = false;
    tx_que = new fxqueue(); pairfd = new pairsock(tx_que);
}
fxtunnel::~fxtunnel()
{
}
int fxtunnel::init(mjson& json_conf, bool _deamon)
{
    int ret = this->_load_config(json_conf);
    if (ret < 0) { return -1; }

#ifdef __linux__
    if (_deamon) {
        xt_daemonize();
    }
#endif

    ret = this->_init();
    if (ret < 0) { return -1; }
    return 0;
}
void fxt_thread(fxtunnel* _fxt)
{
    logd("start fxt_thread");
    _fxt->_run();
    logd("exit fxt_thread");
}
void fxtunnel::run()
{
    main_thread = new std::thread(fxt_thread, this);
}
void fxtunnel::stop()
{
    exit = true;
    _stop();
}
void fxtunnel::reload()
{
    if (run_mode == MODE_SERVER) {
        //reload config file
        logit("Running in server mode. reload config file. Future implementation, please restart");
    } else if (run_mode == MODE_CLIENT) {
        //reload config file
        logit("Running in client mode. reload config file. Future implementation, please restart");
    }
}



//load json config file
int load_config(const char* _config_filepath, mjson& _json_conf)
{
    std::string log_s; std::string mode_s;
    try {
#ifdef _WIN32
        int ret = _access(_config_filepath, 0);
#else
        int ret = access(_config_filepath, 0);
#endif
        if (ret == 0) {
            std::ifstream fin(_config_filepath);
            if (fin.is_open()) {
                char ch; std::string confstr = "";
                while (fin.get(ch)) { confstr += ch; }
                fin.close();
                _json_conf = mjson::parse(confstr);
                //parse log level
                if (_json_conf.find("log_level") != _json_conf.end()) {
                    std::string slog = _json_conf["log_level"];
                    log_s = slog;
                    log_level = get_log_level(log_s);
                }
                //parse running mode
                std::string smode = _json_conf["mode"];
                mode_s = smode;
                if (mode_s == "client") {
                    run_mode = MODE_CLIENT;
                } else if (mode_s == "server") {
                    run_mode = MODE_SERVER;
                } else { throw 0; }
            }
        } else { throw 0; }
    }
    catch (...) {
        logerr("Load configuration file[ %s ] failure", _config_filepath);
        return -1;
    }
    logp("load config ->");
    logp("    log_level: %s", log_s.c_str());
    logp("    mode: %s", mode_s.c_str());
    return 0;
}



#ifdef __linux__

//std::string log_level_s;
std::string pidfile = "fxtunnel.pid";

std::string fifo_rx_filepath;
std::string fifo_tx_filepath;
int	fifo_fdr;
int	fifo_fdw;

int xt_daemonize(const char* _dir) {
    switch (fork()) {
    case -1: return -1;
    case 0: break;
    default: _exit(0);
    }
    if (setsid() == -1) { _exit(0); }
    if (_dir != NULL) { if (chdir(_dir) == -1) { _exit(0); } }
    if (close(STDIN_FILENO) == -1) { _exit(0); }
    if (close(STDOUT_FILENO) == -1) { _exit(0); }
    if (close(STDERR_FILENO) == -1) { _exit(0); }
    int fd = open("/dev/null", O_RDWR, 0); if (fd == -1) { _exit(0); }
    if (dup2(fd, STDIN_FILENO) == -1) { _exit(0); }
    if (dup2(fd, STDOUT_FILENO) == -1) { _exit(0); }
    if (dup2(fd, STDERR_FILENO) == -1) { _exit(0); }
    return 0;
};
int xt_read_pidfile() {
    if (pidfile.empty()) { return -1; }
    std::string s; char buf[256];
    FILE *fp = fopen(pidfile.c_str(), "rb");
    if (!fp) { return -1; }
    while (!feof(fp) && !ferror(fp)) {
        int n = fread(buf, 1, sizeof(buf), fp);
        if (n > 0) { s.append(buf, n); }
    }
    fclose(fp);
    if (s.empty()) { return -1; }
    return strtol(s.c_str(), NULL, 10);
};
void xt_write_pidfile() {
    if (pidfile.empty()) { return; }
    int pid = (int)getpid(); std::string s = std::to_string(pid);
    FILE *fp = fopen(pidfile.c_str(), "wb");
    if (!fp) { logp("Failed to open pidfile for write '%s'. (%s)\n", pidfile.c_str(), strerror(errno)); _exit(1); }
    int ret = fwrite(s.c_str(), 1, s.length(), fp);
    if (ret != s.length()) { fprintf(stderr, "Failed to write pidfile '%s'. (%s)\n", pidfile.c_str(), strerror(errno)); _exit(1); }
    fclose(fp);
};
void xt_check_pidfile() {
    if (pidfile.size()) {
        if (access(pidfile.c_str(), F_OK) == 0) {
            fprintf(stderr, "Pidfile %s already exists!\n"
                "Kill the running process before you run this command.\n",
                pidfile.c_str());
            _exit(1);
        }
    }
};
void xt_remove_pidfile() {
    if (pidfile.size()) { remove(pidfile.c_str()); }
};
void xt_reload_process() {
    int _pid = xt_read_pidfile();
    if (_pid == -1) {
        fprintf(stderr, "could not read pidfile: %s. (%s). \n", pidfile.c_str(), strerror(errno));
        _exit(1);
    }
    if (kill(_pid, 0) == -1 && errno == ESRCH) {
        fprintf(stderr, "process: %d not running\n", _pid);
        xt_remove_pidfile();
        return;
    }
    int ret = kill(_pid, SIGHUP);
    if (ret == -1) {
        fprintf(stderr, "send signal SIGHUP to pid[ %d ] failure. (%s)\n", _pid, strerror(errno));
        _exit(1);
    }
};
bool xt_check_process() {
    int _pid = xt_read_pidfile();
    if (_pid == -1) {
        fprintf(stderr, "could not read pidfile: %s. (%s). \n", pidfile.c_str(), strerror(errno));
        return false;
    }
    if (kill(_pid, 0) == -1 && errno == ESRCH) {
        fprintf(stderr, "process: %d not running\n", _pid);
        xt_remove_pidfile();
        return false;
    }
    return true;
};
void xt_kill_process() {
    int _pid = xt_read_pidfile();
    if (_pid == -1) {
        fprintf(stderr, "could not read pidfile: %s. (%s). \n", pidfile.c_str(), strerror(errno));
        _exit(1);
    }
    if (kill(_pid, 0) == -1 && errno == ESRCH) {
        fprintf(stderr, "process: %d not running\n", _pid);
        xt_remove_pidfile();
        return;
    }
    int ret = kill(_pid, SIGTERM);
    if (ret == -1) {
        fprintf(stderr, "send signal SIGTERM to pid[ %d ] failure. (%s)\n", _pid, strerror(errno));
        _exit(1);
    }
    int now = time(0);
    while (access(pidfile.c_str(), F_OK) == 0) {
        usleep(200 * 1000);
        if (time(0)-now > 5) break;
    }
};
int xt_fifo_init(bool _mode) {
    fifo_rx_filepath = "./fxtunnel.rx.fifo";
    if (access(fifo_rx_filepath.c_str(),F_OK) != 0) {
        mkfifo(fifo_rx_filepath.c_str(),0666);
    }
    fifo_tx_filepath = "./fxtunnel.tx.fifo";
    if( access(fifo_tx_filepath.c_str(),F_OK) != 0) {
        mkfifo(fifo_tx_filepath.c_str(),0666);
    }
    if (_mode) {
        fifo_fdr = open(fifo_rx_filepath.c_str(),O_RDONLY);
        if (fifo_fdr < 0) {
            logp("Open fifo[ %s ] failure. error[ %d : %s ]", fifo_rx_filepath.c_str(), errno, strerror(errno));
            return -1;
        }
        fifo_fdw = open(fifo_tx_filepath.c_str(),O_WRONLY);
        if (fifo_fdw < 0) {
            logp("Open fifo[ %s ] failure. error[ %d : %s ]", fifo_tx_filepath.c_str(), errno, strerror(errno));
            return -1;
        }
    } else {
        fifo_fdr = open(fifo_rx_filepath.c_str(),O_WRONLY);
        if (fifo_fdr < 0) {
            logp("Open fifo[ %s ] failure. error[ %d : %s ]", fifo_rx_filepath.c_str(), errno, strerror(errno));
            return -1;
        }
        fifo_fdw = open(fifo_tx_filepath.c_str(),O_RDONLY);
        if (fifo_fdw < 0) {
            logp("Open fifo[ %s ] failure. error[ %d : %s ]", fifo_tx_filepath.c_str(), errno, strerror(errno));
            return -1;
        }
    }
    return 0;
};
int xt_fifo_read(bool _mode, char* _buf, int _buflen) {
    int ret = 0;
    if (_mode) {
        ret = read(fifo_fdr, _buf, _buflen);
    } else {
        ret = read(fifo_fdw, _buf, _buflen);
    }
    return ret;
};
int xt_fifo_write(bool _mode, const char* _buf, int _buflen) {
    int ret = 0;
    if (_mode) {
        ret = write(fifo_fdw, _buf, _buflen);
    } else {
        ret = write(fifo_fdr, _buf, _buflen);
    }
    return ret;
};
void xt_fifo_close(bool _mode) {
    close(fifo_fdr);
    close(fifo_fdw);
    if (_mode) {
        unlink(fifo_rx_filepath.c_str());
        unlink(fifo_tx_filepath.c_str());
    }
};

#endif

