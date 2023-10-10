#include "typedef.h"
#include "sslclient.h"
#include "sslserver.h"
#include "fxtunnel.h"

int log_level = LOG_INFO;
std::string config_filepath = "fxtunnel.conf";
int run_mode = -1;
fxtunnel* fxt = NULL;


//----------------------------------------------------------
// for linux
//----------------------------------------------------------

#ifdef __linux__
static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        xt_remove_pidfile();
        _exit(0);
    }
}
static void init_signal(void)
{
    struct sigaction sas; memset(&sas, 0, sizeof(sas));
    sas.sa_handler = signal_handler;
    sigemptyset(&sas.sa_mask); sas.sa_flags = 0;
    sigaction(SIGINT, &sas, NULL);
    sigaction(SIGTERM, &sas, NULL);
}
void usage() {
    logp("usage: fxtunnel [start | front | stop | reload | status]");
    logp("    [start]  - daemon running.");
    logp("    [front]  - running in the foreground.");
    logp("    [stop]   - stop program.");
    //logp("    [reload] - reload configuration file\n");
    logp("    [status] - running information.");
}

int main(int argc, char* argv[])
{
    logp("fxtunnel <ppforward.com>");

    init_signal();

    if (argc == 1) { usage(); return 0; }

    std::string cmd = argv[1];
    if (cmd == "stop" || cmd == "status") {
        bool running = xt_check_process();
        if (!running) { return 0; }
        bool fifo_mode = false;
        int ret = xt_fifo_init(fifo_mode);
        if (ret < 0) { logerr("fifo_init( %s ) error",fifo_mode?"true":"false"); return -1; }
        ret = xt_fifo_write(fifo_mode, cmd.c_str(), cmd.length());
        if (ret < 0) { logerr("fifo_write( %s, %s ) error",fifo_mode?"true":"false",cmd.c_str()); return -1; }
        char buf[10240] = { 0 };
        ret = xt_fifo_read(fifo_mode, buf, sizeof(buf));
        if (ret < 0) { logerr("fifo_read( %s, %s ) error",fifo_mode?"true":"false"); return -1; }
        mjson json_resp = mjson::parse(buf);
        int rc = json_resp["rc"]; std::string rmsg = json_resp["rmsg"];
        if (rc != 0) {
            logp("process failure. resp[ %d : %s]", rc, rmsg.c_str());
            return 0;
        }
        if (cmd == "status") {
            //std::string info = json_resp.dump(4);
            std::string info = json_resp["data"];
            logp("%s", info.c_str());
        }
        return 0;
    }
    if (cmd != "start" && cmd != "front") {
        usage();
        return 0;
    }

    xt_check_pidfile();
    xt_write_pidfile();

    mjson json_conf;
    int ret = load_config(config_filepath.c_str(), json_conf);
    if (ret < 0) { return -1; }

    if (run_mode == MODE_SERVER) {
        fxt = new sslserver();
    } else if (run_mode == MODE_CLIENT) {
        fxt = new sslclient();
    }
    bool deamon = true;
    if (cmd == "front") { deamon = false; }
    ret = fxt->init(json_conf, deamon);
    if (ret < 0) { logerr("fxtunnel init failure"); return -1; }
    fxt->run();

    //process fifo command
    bool fifo_mode = true;
    ret = xt_fifo_init(fifo_mode);
    if (ret < 0) { logerr("fifo_init( %s ) error",fifo_mode?"true":"false"); return -1; }
    while (!fxt->exit) {
        char buf[1024] = { 0 };
        ret = xt_fifo_read(fifo_mode, buf, sizeof(buf));
        if (ret < 0) { logerr("fifo_recv() error"); break; }
        else if (ret == 0) { fx_sleep(100); continue; }
        //logp("fifo read commad[ %s ]",buf);

        std::string cmd = buf;
        mjson json_resp; json_resp["rc"] = 0; json_resp["rmsg"] = "Success";
        if (cmd == "stop") {
            std::string resp = json_resp.dump();
            xt_fifo_write(fifo_mode, resp.c_str(), resp.length());
            fxt->stop();
        } else if (cmd == "reload") {
            json_resp["rc"] = 10001; json_resp["rmsg"] = "Future implementation";
            std::string resp = json_resp.dump();
            xt_fifo_write(fifo_mode, resp.c_str(), resp.length());
            fxt->reload();
        } else if (cmd == "status") {
            std::string info_str = fxt->get_format_running_info();
            json_resp["data"] = info_str;
            std::string resp = json_resp.dump();
            xt_fifo_write(fifo_mode, resp.c_str(), resp.length());
        } else {
            logp("fifo receive unknown command[ %s ]", cmd.c_str());
        }
    }
    xt_fifo_close(fifo_mode);

    xt_remove_pidfile();
    return 0;
}

#endif




//----------------------------------------------------------
// for windows
//----------------------------------------------------------

#ifdef _WIN32

#include "resource.h"

//show detail in menu
#define _MENU_SHOW_DETAILS 0

//output log window
#define _WIN32_LOG 0


#define ID_TIMER 1
#define IDR_SEPARATOR_LINE 10
#define IDR_MWINDOW 11
#define IDR_DRAW_MENU  14
#define IDR_RUNNING_INFORMATION 15
#define IDR_CONFIG_FILE  16
#define IDR_EXIT 20

LPCTSTR szAppName = TEXT("FxTunnle");
HINSTANCE hIns;
mjson r_info;

//trayicon
NOTIFYICONDATA nid;
UINT WM_TASKBARCREATED;
HMENU hMenuPopup;
POINT pt;//mouse position
int mid;//selected menu

LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

void init_shellNotifyIcon(HWND hwnd)
{
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 0;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER;
    nid.hIcon = LoadIcon(hIns, MAKEINTRESOURCE(IDD_APP_ICON)); //load from resource.rc
    std::string tips = szAppName;
    if (run_mode == MODE_SERVER) { tips += TEXT(" Server"); }
    else if (run_mode == MODE_CLIENT) { tips += TEXT(" Client"); }
    lstrcpy(nid.szTip, tips.c_str());
    Shell_NotifyIcon(NIM_ADD, &nid);
}
void popupmenu_process(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
    fxt->get_running_info(r_info);

    hMenuPopup = CreatePopupMenu();//create menu

    AppendMenu(hMenuPopup, MF_STRING | MF_OWNERDRAW, IDR_MWINDOW, TEXT("FxTunnel"));
    AppendMenu(hMenuPopup, MF_SEPARATOR | MF_OWNERDRAW, IDR_SEPARATOR_LINE, NULL);
#if _MENU_SHOW_DETAILS
    AppendMenu(hMenuPopup, MF_STRING | MF_OWNERDRAW, IDR_DRAW_MENU, TEXT("Empty"));
    AppendMenu(hMenuPopup, MF_SEPARATOR | MF_OWNERDRAW, IDR_SEPARATOR_LINE, NULL);
#endif
    AppendMenu(hMenuPopup, MF_STRING | MF_OWNERDRAW, IDR_RUNNING_INFORMATION, TEXT("Running Information"));
    AppendMenu(hMenuPopup, MF_SEPARATOR | MF_OWNERDRAW, IDR_SEPARATOR_LINE, NULL);
    AppendMenu(hMenuPopup, MF_STRING | MF_OWNERDRAW, IDR_CONFIG_FILE, TEXT("Config File"));
    AppendMenu(hMenuPopup, MF_SEPARATOR | MF_OWNERDRAW, IDR_SEPARATOR_LINE, NULL);
    AppendMenu(hMenuPopup, MF_STRING | MF_OWNERDRAW, IDR_EXIT, TEXT("Exit"));

    MENUINFO mi = { 0 };
    mi.cbSize = sizeof(mi);
    mi.fMask = MIM_BACKGROUND | MIM_APPLYTOSUBMENUS;
    HBRUSH hBgBrush = ::CreateSolidBrush(RGB(43, 43, 43));
    mi.hbrBack = hBgBrush;
    SetMenuInfo(hMenuPopup, &mi);

    SetMenuDefaultItem(hMenuPopup, 0, TRUE); //Make first menu item the default (bold font)
    EnableMenuItem(hMenuPopup, 0, MF_GRAYED);//Make a certain item in the menu gray out

    GetCursorPos(&pt);//Take mouse coordinates
    ::SetForegroundWindow(hwnd);//Solve the problem of left clicking on the menu without disappearing
    int mid = TrackPopupMenu(hMenuPopup, TPM_RETURNCMD, pt.x - 200, pt.y, NULL, hwnd, NULL);
    if (mid == IDR_MWINDOW) {
        ;
    } else if (mid == IDR_DRAW_MENU) {
        ;
    } else if (mid == IDR_RUNNING_INFORMATION) {
        DialogBox(hIns, MAKEINTRESOURCE(DLG_INFO), NULL, (DLGPROC)DlgProc);
    }
    else if (mid == IDR_CONFIG_FILE) {
        ShellExecute(NULL, TEXT("open"), TEXT("NOTEPAD.EXE"), (TEXT("./") + config_filepath).c_str(), NULL, SW_SHOWNORMAL);
    } else if (mid == IDR_EXIT) {
        SendMessage(hwnd, WM_CLOSE, wParam, lParam);
    }
    DestroyMenu(hMenuPopup);
    return;
}

#define draw_menu_item(str) \
    do { \
        if (lpDrawItemStruct->itemState & ODS_SELECTED) { \
            ::FillRect(hdc, &rc, hBgHoverBrush); \
        } \
        ::SelectObject(hdc, hLargeFont); \
        int pos_y = rc.top + 9; \
        std::string menu_text = str; \
        TextOut(hdc, pos_x, pos_y, menu_text.c_str(), menu_text.length()); \
    } while(0)

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    WM_TASKBARCREATED = RegisterWindowMessage(TEXT("TaskbarCreated")); // don't modify. system default
    switch (message) {
        case WM_CREATE: {
            init_shellNotifyIcon(hwnd);
            break;
        }
        case WM_USER: {
            if (lParam == WM_LBUTTONDBLCLK || lParam == WM_LBUTTONDOWN || lParam == WM_RBUTTONDOWN) {
                popupmenu_process(hwnd, wParam, lParam);
            }
            break;
        }
        case WM_MEASUREITEM: {
            MEASUREITEMSTRUCT* lpMeasureItemStruct = (MEASUREITEMSTRUCT*)lParam;
            if (lpMeasureItemStruct->CtlType != ODT_MENU) { break; }
            lpMeasureItemStruct->itemWidth = 320;
            if (lpMeasureItemStruct->itemID == IDR_MWINDOW) {
                lpMeasureItemStruct->itemHeight = 100;
            }
#if _MENU_SHOW_DETAILS
            else if (lpMeasureItemStruct->itemID == IDR_DRAW_MENU) {
                if (run_mode == MODE_CLIENT) {
                    if (r_info["services"].size() == 0) {
                        lpMeasureItemStruct->itemHeight = 40;
                    } else {
                        lpMeasureItemStruct->itemHeight = 123 * r_info["services"].size();
                    }
                } else if (run_mode == MODE_SERVER) {
                    if (r_info["links"].size() == 0) {
                        lpMeasureItemStruct->itemHeight = 40;
                    } else {
                        lpMeasureItemStruct->itemHeight = 67 * r_info["links"].size();
                    }
                }
            }
#endif
            else if (lpMeasureItemStruct->itemID == IDR_RUNNING_INFORMATION) {
                lpMeasureItemStruct->itemHeight = 40;
            } else if (lpMeasureItemStruct->itemID == IDR_CONFIG_FILE) {
                lpMeasureItemStruct->itemHeight = 40;
            } else if (lpMeasureItemStruct->itemID == IDR_EXIT) {
                lpMeasureItemStruct->itemHeight = 40;
            } else if (lpMeasureItemStruct->itemID == IDR_SEPARATOR_LINE) {
                lpMeasureItemStruct->itemHeight = 9;
            }
            break;
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* lpDrawItemStruct = (DRAWITEMSTRUCT*)lParam;
            HDC hdc = lpDrawItemStruct->hDC;
            RECT rc = lpDrawItemStruct->rcItem;
            ::SetBkMode(hdc, TRANSPARENT);
            HFONT hOldFont; HPEN hOldPen; HBRUSH hOldBrush;
            HFONT hNormalFont = CreateFont(18, 0, 0, 0, FW_REGULAR, 0, 0, 0, GB2312_CHARSET, 0, 0, 0, 0, TEXT("Microsoft YaHei"));
            HFONT hLargeFont = CreateFont(20, 0, 0, 0, FW_REGULAR, 0, 0, 0, GB2312_CHARSET, 0, 0, 0, 0, TEXT("Microsoft YaHei"));
            HBRUSH hBgBrush = ::CreateSolidBrush(RGB(43, 43, 43));
            HBRUSH hBgHoverBrush = ::CreateSolidBrush(RGB(65, 65, 65));
            HPEN hSeparatorLinePen = CreatePen(PS_SOLID, 1, RGB(128, 128, 128));
            HPEN hThinPen = CreatePen(PS_SOLID, 1, RGB(80, 80, 80));
            HBRUSH hRedIconBrush = ::CreateSolidBrush(RGB(221, 85, 85));
            HBRUSH hGreenIconBrush = ::CreateSolidBrush(RGB(85, 221, 130));
            HBRUSH hGrayIconBrush = ::CreateSolidBrush(RGB(104, 104, 104));

            hOldFont = (HFONT)::SelectObject(hdc, hNormalFont);
            SetTextColor(hdc, RGB(255, 255, 255));
            ::FillRect(hdc, &rc, hBgBrush);

            int pos_x = rc.left + 21;
            if (lpDrawItemStruct->itemID == IDR_MWINDOW) {
                int pos_y = rc.top + 16;
                ::SelectObject(hdc, hLargeFont);
                std::string tips = TEXT("FxTunnel Server");
                if (run_mode == MODE_CLIENT) { tips = TEXT("FxTunnel Client"); }
                TextOut(hdc, pos_x, pos_y, tips.c_str(), tips.length());

                if (run_mode == MODE_CLIENT) {
                    tips = TEXT("Server Address  ");
                    std::string connect_addr = r_info["connect_addr"];
                    int port_ = r_info["connect_port"];
                    std::string port = std::to_string(port_);
                    tips += connect_addr + TEXT("  ") + std::to_string(port_);
                    pos_y += 32;
                    ::SelectObject(hdc, hNormalFont);
                    TextOut(hdc, pos_x, pos_y, tips.c_str(), tips.length());

                    //draw running state
                    int state = r_info["state"];
                    if (state == 0) {
                        hOldBrush = (HBRUSH)::SelectObject(hdc, hGrayIconBrush);
                        tips = TEXT(" connecting...");
                    } else if (state == 1) {
                        hOldBrush = (HBRUSH)::SelectObject(hdc, hGreenIconBrush);
                        tips = TEXT(" connected");
                    } else {
                        hOldBrush = (HBRUSH)::SelectObject(hdc, hRedIconBrush);
                        if (state == 2) {
                            tips = TEXT(" Authentication failed");
                        } else if (state == 3) {
                            tips = TEXT(" Kicked out by other connections");
                        } else {
                            tips = TEXT(" connect failed");
                        }
                    }
                    pos_y += 28;
                    Ellipse(hdc, pos_x, pos_y, pos_x + 12, pos_y + 12);
                    ::SelectObject(hdc, hOldBrush);
                    pos_y -= 3;
                    ::SelectObject(hdc, hNormalFont);
                    TextOut(hdc, pos_x + 24, pos_y, tips.c_str(), tips.length());
                } else {
                    // server mode
                    hOldBrush = (HBRUSH)::SelectObject(hdc, hGreenIconBrush);
                    tips = TEXT(" Listen Port  ");
                    int listen_port = r_info["listen_port"];
                    tips += std::to_string(listen_port);
                    pos_y += 32;
                    Ellipse(hdc, pos_x, pos_y, pos_x + 12, pos_y + 12);
                    ::SelectObject(hdc, hOldBrush);
                    pos_y -= 3;
                    ::SelectObject(hdc, hNormalFont);
                    TextOut(hdc, pos_x + 24, pos_y, tips.c_str(), tips.length());

                    //Output the number of connected clients
                    pos_y += 25;
                    tips = TEXT("Number of connected clients  ");
                    int link_count = r_info["link_count"];
                    tips += std::to_string(link_count);
                    ::SelectObject(hdc, hNormalFont);
                    TextOut(hdc, pos_x, pos_y, tips.c_str(), tips.length());
                }                
            }
#if _MENU_SHOW_DETAILS
            else if (lpDrawItemStruct->itemID == IDR_DRAW_MENU) {
                int pos_y = rc.top;
                if (run_mode == MODE_CLIENT) {
                    int top_offset = -4;
                    if (r_info["services"].size() == 0) {
                        top_offset += 15;
                        SetTextColor(hdc, RGB(160, 160, 160));
                        std::string s = TEXT("No Port Configuration");
                        TextOut(hdc, pos_x, pos_y + top_offset, s.c_str(), s.length());
                    } else {
                        int cnt = 0;
                        for (auto& iter : r_info["services"]) {
                            mjson json_svr = iter;
                            //draw service information
                            std::string name = json_svr["name"];
                            std::string addr = json_svr["connect_addr"];
                            int port_ = json_svr["connect_port"];
                            std::string port = std::to_string(port_);
                            int protocol_ = json_svr["protocol"];
                            std::string protocol = PROTOCOL_S(protocol_);
                            int mapped_port_ = json_svr["mapped_port"];
                            std::string mapped_port = std::to_string(mapped_port_);
                            ::SelectObject(hdc, hNormalFont);
                            SetTextColor(hdc, RGB(176, 226, 255));
                            top_offset += 18;
                            TextOut(hdc, pos_x, pos_y + top_offset, name.c_str(), name.length());

                            std::string sline_1, s1ine_2;
                            if (run_mode == MODE_CLIENT) {
                                if (protocol_ == PROTOCOL_TCP_SC || protocol_ == PROTOCOL_UDP_SC) {
                                    sline_1 = TEXT(" -  Local Mapped Port  ") + protocol + TEXT("  ") + mapped_port;
                                    s1ine_2 = TEXT(" -  Destination Address  ") + addr + TEXT("  ") + port;
                                } else if (protocol_ == PROTOCOL_TCP_SA || protocol_ == PROTOCOL_UDP_SA) {
                                    sline_1 = TEXT(" -  Server Mapped Port  ") + protocol + TEXT("  ") + mapped_port;
                                    s1ine_2 = TEXT(" -  Destination Address  ") + addr + TEXT("  ") + port;
                                }
                            } else if (run_mode == MODE_SERVER) {
                                if (protocol_ == PROTOCOL_TCP_SA || protocol_ == PROTOCOL_UDP_SA) {
                                    sline_1 = TEXT(" -  Local Mapped Port  ") + protocol + TEXT("  ") + mapped_port;
                                    s1ine_2 = TEXT(" -  Destination Address  ") + addr + TEXT("  ") + port;
                                } else if (protocol_ == PROTOCOL_TCP_SC || protocol_ == PROTOCOL_UDP_SC) {
                                    sline_1 = TEXT(" -  Client Mapped Port  ") + protocol + TEXT("  ") + mapped_port;
                                    s1ine_2 = TEXT(" -  Destination Address  ") + addr + TEXT("  ") + port;
                                }
                            }
                            ::SelectObject(hdc, hNormalFont);
                            SetTextColor(hdc, RGB(185, 224, 255));
                            top_offset += 30;
                            TextOut(hdc, pos_x, pos_y + top_offset, sline_1.c_str(), sline_1.length());

                            top_offset += 24;
                            TextOut(hdc, pos_x, pos_y + top_offset, s1ine_2.c_str(), s1ine_2.length());

                            top_offset += 24;
                            int session_count_ = json_svr["session_count"];
                            std::string session_count = std::to_string(session_count_);
                            std::string sss = TEXT(" -  Number of connections  ") + session_count;
                            TextOut(hdc, pos_x, pos_y + top_offset, sss.c_str(), sss.length());

                            if ((cnt + 1) == r_info["services"].size()) { break; }

                            // draw separator lines
                            hOldPen = (HPEN)::SelectObject(hdc, hThinPen);
                            top_offset += 26;
                            MoveToEx(hdc, pos_x, pos_y + top_offset, NULL); LineTo(hdc, pos_x + 258, pos_y + top_offset);
                            ::SelectObject(hdc, hOldPen);
                            cnt++;
                        }
                    }
                } else if (run_mode == MODE_SERVER) {
                    int top_offset = 0;
                    if (r_info["links"].size() == 0) {
                        top_offset += 12;
                        SetTextColor(hdc, RGB(160, 160, 160));
                        std::string s = TEXT("No Port Configuration");
                        TextOut(hdc, pos_x, pos_y + top_offset, s.c_str(), s.length());
                    } else {
                        int cnt = 0;
                        for (auto& iter : r_info["links"]) {
                            mjson json_link = iter;
                            //draw client information
                            std::string authkey = json_link["authkey"];
                            bool connected = json_link["connected"];
                            std::string connected_s = connected ? "Connected":"Not Connected";
                            std::string ipaddr = json_link["ipaddr"];
                            int port_ = json_link["port"];
                            std::string port = std::to_string(port_);
                            int network_delay_ = json_link["network_delay"];
                            std::string network_delay = std::to_string(network_delay_);

                            std::string text = TEXT("Client AuthKey  ") + authkey;
                            top_offset += 15;
                            //::SelectObject(hdc, hLargeFont);
                            SetTextColor(hdc, RGB(176, 226, 255));
                            TextOut(hdc, pos_x, pos_y + top_offset, text.c_str(), text.length());

                            if (connected) {
                                hOldBrush = (HBRUSH)::SelectObject(hdc, hGreenIconBrush);
                                text = connected_s + TEXT("  ") + ipaddr + TEXT(" ") + port;
                            } else {
                                text = connected_s;
                                hOldBrush = (HBRUSH)::SelectObject(hdc, hGrayIconBrush);
                            }
                            top_offset += 24;
                            int offset = 3;
                            Ellipse(hdc, pos_x, pos_y + top_offset + offset, pos_x + 12, pos_y + top_offset + offset + 12);
                            ::SelectObject(hdc, hOldBrush);
                            TextOut(hdc, pos_x + 24, pos_y + top_offset, text.c_str(), text.length());

                            if ((cnt + 1) == r_info["links"].size()) { break; }

                            // draw separator lines
                            hOldPen = (HPEN)::SelectObject(hdc, hThinPen);
                            top_offset += 28;
                            MoveToEx(hdc, pos_x, pos_y + top_offset, NULL); LineTo(hdc, pos_x + 258, pos_y + top_offset);
                            ::SelectObject(hdc, hOldPen);
                            cnt++;
                        }
                    }
                }
            }
#endif
            else if (lpDrawItemStruct->itemID == IDR_RUNNING_INFORMATION) {
                draw_menu_item(TEXT("Running Information"));
                /*
                if (lpDrawItemStruct->itemState & ODS_SELECTED) {
                    ::FillRect(hdc, &rc, hBgHoverBrush);
                }
                ::SelectObject(hdc, hLargeFont);
                int pos_y = rc.top + 9;
                std::string menu_text = TEXT("Running Information");
                TextOut(hdc, pos_x, pos_y, menu_text.c_str(), menu_text.length());
                */
            }
            else if (lpDrawItemStruct->itemID == IDR_CONFIG_FILE) {
                draw_menu_item(TEXT("Configuration File"));
            }
            else if (lpDrawItemStruct->itemID == IDR_EXIT) {
                draw_menu_item(TEXT("Exit"));
            }
            else if (lpDrawItemStruct->itemID == IDR_SEPARATOR_LINE) {
                // draw separator lines
                hOldPen = (HPEN)::SelectObject(hdc, hSeparatorLinePen);
                MoveToEx(hdc, pos_x - 16, rc.top + 4, NULL); LineTo(hdc, pos_x + 272 - 12, rc.top + 4);
                ::SelectObject(hdc, hOldPen);
            }
            ::DeleteObject(hNormalFont);
            ::DeleteObject(hLargeFont);
            ::DeleteObject(hBgBrush);
            ::DeleteObject(hBgHoverBrush);
            ::DeleteObject(hSeparatorLinePen);
            ::DeleteObject(hThinPen);
            ::DeleteObject(hRedIconBrush);
            ::DeleteObject(hGrayIconBrush);
            ::DeleteObject(hGreenIconBrush);
            ::DeleteObject(hRedIconBrush);
            break;
        }
        case WM_DESTROY: {
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
        }
        default: {
            // Prevent the icon of the program from disappearing in the system tray when Explorer.exe crashes
            if (message == WM_TASKBARCREATED)
                SendMessage(hwnd, WM_CREATE, wParam, lParam);
            break;
        }
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
            //center windows
            int scr_w = GetSystemMetrics(SM_CXSCREEN);
            int scr_h = GetSystemMetrics(SM_CYSCREEN);
            RECT rect;
            GetWindowRect(hDlg, &rect);
            long width = rect.right - rect.left;
            long height = rect.bottom - rect.top;
            rect.left = (scr_w - width) / 2;
            rect.top = (scr_h - height) / 2;
            SetWindowPos(hDlg, HWND_TOP, rect.left, rect.top, width, height, SWP_NOSIZE | SWP_NOZORDER);

            //set edit readonly
            HWND hedit = ::GetDlgItem(hDlg, DLG_EDIT);
            ::PostMessage(hedit, EM_SETREADONLY, 1, 0);
            //set text
            std::string info_str = fxt->get_format_running_info();
            SetWindowText(hedit, info_str.c_str());
            //scroll to top
            ::PostMessage(hedit, WM_VSCROLL, SB_TOP, 0);
            break;
        }
        case WM_COMMAND: {
            if (DLG_BTN_REFRESH == LOWORD(wParam)) {
                HWND hedit = ::GetDlgItem(hDlg, DLG_EDIT);
                //set text
                std::string info_str = fxt->get_format_running_info();
                SetWindowText(hedit, info_str.c_str());
                //scroll to top
                ::PostMessage(hedit, WM_VSCROLL, SB_TOP, 0);
            }
            break;
        }
        case WM_CLOSE: {
            EndDialog(hDlg, 0);
            break;
        }
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR szCmdLine, int iCmdShow)
{
    hIns = hInstance;

#if _WIN32_LOG
    //Log Output Window
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
#endif

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    HWND handle = FindWindow(NULL, szAppName);
    if (handle != NULL) {
        MessageBox(NULL, TEXT("Application is already running"), szAppName, MB_ICONERROR);
        return 0;
    }

    mjson json_conf;
    int ret = load_config(config_filepath.c_str(), json_conf);
    if (ret < 0) { return -1; }

    if (run_mode == MODE_SERVER) {
        fxt = new sslserver();
    } else if (run_mode == MODE_CLIENT) {
        fxt = new sslclient();
    }
    ret = fxt->init(json_conf);
    if (ret < 0) { logerr("fxtunnel init failure"); return -1; }
    fxt->run();

    HWND hwnd; MSG msg; WNDCLASS wndclass;
    wndclass.style = CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc = WndProc;
    wndclass.cbClsExtra = 0;
    wndclass.cbWndExtra = 0;
    wndclass.hInstance = hInstance;
    wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wndclass.lpszMenuName = NULL;
    wndclass.lpszClassName = szAppName;
    if (!RegisterClass(&wndclass)) {
        MessageBox(NULL, TEXT("This program requires Windows NT!"), szAppName, MB_ICONERROR);
        return 0;
    }
    // Using WS_ EX_ The TOOLWINDOW property to hide window program buttons displayed on the taskbar
    hwnd = CreateWindowEx(WS_EX_TOOLWINDOW, szAppName, szAppName,
        WS_POPUP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, iCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    fxt->stop();

    WSACleanup();

#if _WIN32_LOG
    //Log output window
    FreeConsole();
    fflush(stdout);
#endif

    return msg.wParam;
}

#endif

