// SPDX-License-Identifier: GPL-3.0-or-later
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include "build_secrets.h"

#define APP_TITLE L"Rolas Electronics Zdalna Pomoc"
#define SERVICE_NAME L"uvnc_service"
#define PRODUCT_KEY L"Software\\Rolas Electronics\\Pomoc Rolas"
#define RUN_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_VALUE L"Pomoc Rolas"
#define IDR_WINVNC_X64 101
#define IDR_HOOKS_X64 102
#define IDR_DD_X64 103
#define IDR_DSM_X64 104
#define IDR_WINVNC_X86 111
#define IDR_HOOKS_X86 112
#define IDR_DD_X86 113
#define IDR_DSM_X86 114
#define IDI_APP 201
#define IDB_LOGO 202
#define TIMER_CHILD 1
#define IDC_PERSISTENT 1001
#define WM_TRAYICON (WM_APP + 10)
#define IDM_OPEN 2001
#define IDM_DISABLE 2002
#define IDM_EXIT_TRAY 2003

static HWND g_window, g_persistent_button;
static HANDLE g_child, g_job;
static WCHAR g_session_dir[MAX_PATH], g_id[7];
static HFONT g_font_id, g_font_ui;
static HBITMAP g_logo;
static HICON g_icon;
static BOOL g_persistent, g_tray_mode, g_tray_added;

static void path_join(WCHAR *out, const WCHAR *dir, const WCHAR *file) {
    wsprintfW(out, L"%s\\%s", dir, file);
}

static BOOL write_bytes(const WCHAR *path, const void *data, DWORD size) {
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    DWORD written=0; BOOL ok=WriteFile(file,data,size,&written,NULL)&&written==size;
    FlushFileBuffers(file);CloseHandle(file);return ok;
}

static BOOL extract_resource(WORD id,const WCHAR *path) {
    HRSRC r=FindResourceW(NULL,MAKEINTRESOURCEW(id),MAKEINTRESOURCEW(10));
    if(!r)return FALSE; HGLOBAL h=LoadResource(NULL,r); if(!h)return FALSE;
    DWORD size=SizeofResource(NULL,r);const void *data=LockResource(h);
    return data&&size&&write_bytes(path,data,size);
}

static BOOL native_is_64bit(void) {
    BOOL wow64=FALSE;if(IsWow64Process(GetCurrentProcess(),&wow64)&&wow64)return TRUE;
    SYSTEM_INFO i;GetNativeSystemInfo(&i);
    return i.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64||
           i.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64;
}

static BOOL generate_id(void) {
    HCRYPTPROV p=0;uint32_t v=0;
    if(!CryptAcquireContextW(&p,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))return FALSE;
    BOOL ok=CryptGenRandom(p,sizeof(v),(BYTE*)&v);CryptReleaseContext(p,0);if(!ok)return FALSE;
    v=200000u+v%800000u;wsprintfW(g_id,L"%06u",v);return TRUE;
}

static BOOL write_ultravnc_ini(const WCHAR *dir,BOOL persistent,const WCHAR *id) {
    WCHAR path[MAX_PATH];path_join(path,dir,L"ultravnc.ini");BOOL x64=native_is_64bit();
    char service[256]="";
    if(persistent){
        char id8[16];WideCharToMultiByte(CP_ACP,0,id,-1,id8,sizeof(id8),NULL,NULL);
        snprintf(service,sizeof(service),
          "service_commandline=-autoreconnect ID:%s -connect %s::%d\r\n",
          id8,ROLAS_REPEATER_HOST_A,ROLAS_REPEATER_PORT);
    }
    char ini[3072];
    int n=snprintf(ini,sizeof(ini),
      "[admin]\r\nSocketConnect=1\r\nHTTPConnect=0\r\nAutoPortSelect=0\r\n"
      "AuthRequired=1\r\nReverseAuthRequired=1\r\nSecure=0\r\nAllowLoopback=0\r\n"
      "InputsEnabled=1\r\nLocalInputsDisabled=0\r\nFileTransferEnabled=1\r\n"
      "FTUserImpersonation=1\r\nBlankMonitorEnabled=0\r\nDisableTrayIcon=1\r\n"
      "AllowProperties=0\r\nAllowEditClients=0\r\nAllowShutdown=0\r\n"
      "QuerySetting=2\r\nQueryIfNoLogon=0\r\nRemoveWallpaper=1\r\n"
      "RemoveEffects=0\r\nRemoveFontSmoothing=0\r\nEnableUnicodeInput=1\r\n"
      "UseDSMPlugin=1\r\nDSMPlugin=%s\r\n"
      "DSMPluginConfig=SecureVNC;0;0x00104001;%s\r\n%sDebugMode=0\r\n"
      "[UltraVNC]\r\npasswd=%s\r\npasswd2=%s\r\n",
      x64?"SecureVNCPlugin64.dsm":"SecureVNCPlugin.dsm",
      ROLAS_SECUREVNC_PASSPHRASE_B64,service,
      ROLAS_UVNC_PASSWORD_HEX,ROLAS_UVNC_PASSWORD_HEX);
    return n>0&&n<(int)sizeof(ini)&&write_bytes(path,ini,(DWORD)n);
}

static BOOL extract_payload(const WCHAR *dir,const WCHAR *server_name) {
    WCHAR path[MAX_PATH];BOOL x64=native_is_64bit();
    path_join(path,dir,server_name);if(!extract_resource(x64?IDR_WINVNC_X64:IDR_WINVNC_X86,path))return FALSE;
    path_join(path,dir,L"vnchooks.dll");if(!extract_resource(x64?IDR_HOOKS_X64:IDR_HOOKS_X86,path))return FALSE;
    path_join(path,dir,x64?L"ddengine64.dll":L"ddengine.dll");if(!extract_resource(x64?IDR_DD_X64:IDR_DD_X86,path))return FALSE;
    path_join(path,dir,x64?L"SecureVNCPlugin64.dsm":L"SecureVNCPlugin.dsm");if(!extract_resource(x64?IDR_DSM_X64:IDR_DSM_X86,path))return FALSE;
    path_join(path,dir,L"ultravnc.portable");return write_bytes(path,"",0);
}

static BOOL prepare_payload(WCHAR *server) {
    WCHAR temp[MAX_PATH];if(!GetTempPathW(MAX_PATH,temp))return FALSE;
    wsprintfW(g_session_dir,L"%sRolasPomoc-%lu",temp,GetCurrentProcessId());
    CreateDirectoryW(g_session_dir,NULL);path_join(server,g_session_dir,L"winvnc.exe");
    return extract_payload(g_session_dir,L"winvnc.exe")&&write_ultravnc_ini(g_session_dir,FALSE,NULL);
}

static BOOL service_exists(void) {
    BOOL found=FALSE;SC_HANDLE m=OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT);
    if(m){SC_HANDLE s=OpenServiceW(m,SERVICE_NAME,SERVICE_QUERY_STATUS);
      if(s){found=TRUE;CloseServiceHandle(s);}CloseServiceHandle(m);}return found;
}

static BOOL read_fixed_id(void) {
    HKEY key;DWORD type=0,size=sizeof(g_id);
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,PRODUCT_KEY,0,KEY_READ,&key)!=ERROR_SUCCESS)return FALSE;
    LONG r=RegQueryValueExW(key,L"ID",NULL,&type,(BYTE*)g_id,&size);RegCloseKey(key);
    if(r!=ERROR_SUCCESS||type!=REG_SZ||lstrlenW(g_id)!=6)return FALSE;
    for(int i=0;i<6;i++)if(g_id[i]<L'0'||g_id[i]>L'9')return FALSE;
    return TRUE;
}

static BOOL start_support(void) {
    WCHAR server[MAX_PATH];if(!generate_id()||!prepare_payload(server))return FALSE;
    WCHAR ini[MAX_PATH],cmd[1024];path_join(ini,g_session_dir,L"ultravnc.ini");
    wsprintfW(cmd,L"\"%s\" -config \"%s\" -multi -autoreconnect id:%s -connect %s::%d -run",
      server,ini,g_id,ROLAS_REPEATER_HOST_W,ROLAS_REPEATER_PORT);
    STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={0};
    g_job=CreateJobObjectW(NULL,NULL);
    if(g_job){JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim={0};
      lim.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      SetInformationJobObject(g_job,JobObjectExtendedLimitInformation,&lim,sizeof(lim));}
    if(!CreateProcessW(server,cmd,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,g_session_dir,&si,&pi))return FALSE;
    if(g_job&&!AssignProcessToJobObject(g_job,pi.hProcess)){
      TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    g_child=pi.hProcess;ResumeThread(pi.hThread);CloseHandle(pi.hThread);
    SetTimer(g_window,TIMER_CHILD,1000,NULL);return TRUE;
}

static void stop_support(void) {
    KillTimer(g_window,TIMER_CHILD);if(g_job){CloseHandle(g_job);g_job=NULL;}
    else if(g_child)TerminateProcess(g_child,0);
    if(g_child){WaitForSingleObject(g_child,3000);CloseHandle(g_child);g_child=NULL;}
}

static void cleanup_files(void) {
    if(!g_session_dir[0])return;WCHAR p[MAX_PATH];
    const WCHAR *files[]={L"winvnc.exe",L"vnchooks.dll",L"ddengine.dll",L"ddengine64.dll",
      L"SecureVNCPlugin.dsm",L"SecureVNCPlugin64.dsm",L"ultravnc.ini",L"ultravnc.portable",
      L"msrc4plugin.dsm.log",L"WinVNC.log",NULL};
    for(int i=0;files[i];i++){path_join(p,g_session_dir,files[i]);DeleteFileW(p);}
    RemoveDirectoryW(g_session_dir);g_session_dir[0]=0;
}

static BOOL get_install_dir(WCHAR *dir) {
    WCHAR base[MAX_PATH],vendor[MAX_PATH];
    if(!GetEnvironmentVariableW(L"ProgramFiles",base,MAX_PATH))return FALSE;
    path_join(vendor,base,L"Rolas Electronics");CreateDirectoryW(vendor,NULL);
    path_join(dir,vendor,L"Pomoc Rolas");CreateDirectoryW(dir,NULL);
    return GetFileAttributesW(dir)!=INVALID_FILE_ATTRIBUTES;
}

static DWORD run_wait(const WCHAR *exe,const WCHAR *args,const WCHAR *dir) {
    WCHAR cmd[1024];wsprintfW(cmd,L"\"%s\" %s",exe,args);
    STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={0};
    if(!CreateProcessW(exe,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,dir,&si,&pi))return (DWORD)-1;
    CloseHandle(pi.hThread);WaitForSingleObject(pi.hProcess,30000);
    DWORD code=1;GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hProcess);return code;
}

static int install_persistent(const WCHAR *id) {
    WCHAR dir[MAX_PATH],app[MAX_PATH],server[MAX_PATH],source[MAX_PATH],run[2*MAX_PATH];
    if(service_exists())return 9;
    if(!get_install_dir(dir))return 2;GetModuleFileNameW(NULL,source,MAX_PATH);
    path_join(app,dir,L"Pomoc-Rolas.exe");path_join(server,dir,L"winvnc.exe");
    if(!CopyFileW(source,app,FALSE)||!extract_payload(dir,L"winvnc.exe")||!write_ultravnc_ini(dir,TRUE,id))return 3;
    HKEY key;if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,PRODUCT_KEY,0,NULL,0,KEY_WRITE,NULL,&key,NULL)!=ERROR_SUCCESS)return 4;
    RegSetValueExW(key,L"ID",0,REG_SZ,(BYTE*)id,(lstrlenW(id)+1)*sizeof(WCHAR));RegCloseKey(key);
    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,RUN_KEY,0,NULL,0,KEY_WRITE,NULL,&key,NULL)!=ERROR_SUCCESS)return 5;
    wsprintfW(run,L"\"%s\" --tray",app);RegSetValueExW(key,RUN_VALUE,0,REG_SZ,(BYTE*)run,(lstrlenW(run)+1)*sizeof(WCHAR));RegCloseKey(key);
    run_wait(server,L"-install",dir);return service_exists()?0:6;
}

static int remove_persistent(void) {
    WCHAR dir[MAX_PATH],path[MAX_PATH];if(!get_install_dir(dir))return 2;
    path_join(path,dir,L"winvnc.exe");if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES)run_wait(path,L"-uninstall",dir);
    HKEY key;if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,RUN_KEY,0,KEY_SET_VALUE,&key)==ERROR_SUCCESS){RegDeleteValueW(key,RUN_VALUE);RegCloseKey(key);}
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,PRODUCT_KEY);
    const WCHAR *files[]={L"winvnc.exe",L"vnchooks.dll",L"ddengine.dll",L"ddengine64.dll",
      L"SecureVNCPlugin.dsm",L"SecureVNCPlugin64.dsm",L"ultravnc.ini",L"ultravnc.portable",L"Pomoc-Rolas.exe",NULL};
    for(int i=0;files[i];i++){path_join(path,dir,files[i]);if(!DeleteFileW(path))MoveFileExW(path,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);}
    RemoveDirectoryW(dir);return service_exists()?7:0;
}

static DWORD run_elevated(const WCHAR *params) {
    WCHAR self[MAX_PATH];GetModuleFileNameW(NULL,self,MAX_PATH);
    SHELLEXECUTEINFOW i={sizeof(i)};i.fMask=SEE_MASK_NOCLOSEPROCESS;i.lpVerb=L"runas";
    i.lpFile=self;i.lpParameters=params;i.nShow=SW_HIDE;if(!ShellExecuteExW(&i))return (DWORD)-1;
    WaitForSingleObject(i.hProcess,60000);DWORD code=1;GetExitCodeProcess(i.hProcess,&code);CloseHandle(i.hProcess);return code;
}

static void launch_tray_helper(void) {
    WCHAR dir[MAX_PATH],app[MAX_PATH],cmd[2*MAX_PATH];
    if(!get_install_dir(dir))return;
    path_join(app,dir,L"Pomoc-Rolas.exe");wsprintfW(cmd,L"\"%s\" --tray",app);
    STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={0};
    if(CreateProcessW(app,cmd,NULL,NULL,FALSE,0,NULL,dir,&si,&pi)){
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    }
}

static void add_tray_icon(void) {
    if(g_tray_added)return;NOTIFYICONDATAW d={sizeof(d)};d.hWnd=g_window;d.uID=1;
    d.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;d.uCallbackMessage=WM_TRAYICON;d.hIcon=g_icon;
    lstrcpyW(d.szTip,L"Pomoc Rolas - stały dostęp");g_tray_added=Shell_NotifyIconW(NIM_ADD,&d);
}
static void remove_tray_icon(void) {
    if(!g_tray_added)return;NOTIFYICONDATAW d={sizeof(d)};d.hWnd=g_window;d.uID=1;
    Shell_NotifyIconW(NIM_DELETE,&d);g_tray_added=FALSE;
}

static void enable_persistent(void) {
    WCHAR q[256],params[64];wsprintfW(q,L"Włączyć stały dostęp dla ID %s? Usługa będzie uruchamiana automatycznie wraz z Windows.",g_id);
    if(MessageBoxW(g_window,q,APP_TITLE,MB_YESNO|MB_ICONQUESTION)!=IDYES)return;
    wsprintfW(params,L"--install-service %s",g_id);
    if(run_elevated(params)!=0){MessageBoxW(g_window,L"Nie udało się zainstalować stałego dostępu.",APP_TITLE,MB_OK|MB_ICONERROR);return;}
    stop_support();cleanup_files();launch_tray_helper();
    MessageBoxW(g_window,L"Stały dostęp został włączony. Po restarcie usługa uruchomi się automatycznie z tym samym ID.",APP_TITLE,MB_OK|MB_ICONINFORMATION);
    DestroyWindow(g_window);
}
static void disable_persistent(void) {
    if(MessageBoxW(g_window,L"Wyłączyć i usunąć stały dostęp z tego komputera?",APP_TITLE,MB_YESNO|MB_ICONWARNING)!=IDYES)return;
    if(run_elevated(L"--remove-service")!=0){MessageBoxW(g_window,L"Nie udało się usunąć stałego dostępu.",APP_TITLE,MB_OK|MB_ICONERROR);return;}
    MessageBoxW(g_window,L"Stały dostęp został usunięty.",APP_TITLE,MB_OK|MB_ICONINFORMATION);DestroyWindow(g_window);
}

static void show_tray_menu(void) {
    HMENU m=CreatePopupMenu();AppendMenuW(m,MF_STRING,IDM_OPEN,L"Otwórz Pomoc Rolas");
    AppendMenuW(m,MF_STRING,IDM_DISABLE,L"Wyłącz stały dostęp");AppendMenuW(m,MF_SEPARATOR,0,NULL);
    AppendMenuW(m,MF_STRING,IDM_EXIT_TRAY,L"Zamknij ikonę");
    POINT p;GetCursorPos(&p);SetForegroundWindow(g_window);TrackPopupMenu(m,TPM_RIGHTBUTTON,p.x,p.y,0,g_window,NULL);DestroyMenu(m);
}

static LRESULT CALLBACK window_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg){
    case WM_CREATE:
      g_window=w;g_logo=(HBITMAP)LoadImageW(((LPCREATESTRUCTW)lp)->hInstance,MAKEINTRESOURCEW(IDB_LOGO),IMAGE_BITMAP,0,0,LR_CREATEDIBSECTION);
      g_persistent_button=CreateWindowW(L"BUTTON",g_persistent?L"Wyłącz stały dostęp":L"Włącz stały dostęp",
        WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,125,205,200,34,w,(HMENU)IDC_PERSISTENT,((LPCREATESTRUCTW)lp)->hInstance,NULL);
      SendMessageW(g_persistent_button,WM_SETFONT,(WPARAM)g_font_ui,TRUE);
      if(g_persistent)add_tray_icon();else PostMessageW(w,WM_APP+1,0,0);return 0;
    case WM_APP+1:
      if(!start_support()){MessageBoxW(w,L"Nie udało się przygotować połączenia.",APP_TITLE,MB_OK|MB_ICONERROR);DestroyWindow(w);}
      InvalidateRect(w,NULL,FALSE);return 0;
    case WM_COMMAND:
      if(LOWORD(wp)==IDC_PERSISTENT){if(g_persistent)disable_persistent();else enable_persistent();return 0;}
      if(LOWORD(wp)==IDM_OPEN){ShowWindow(w,SW_RESTORE);SetForegroundWindow(w);return 0;}
      if(LOWORD(wp)==IDM_DISABLE){disable_persistent();return 0;}
      if(LOWORD(wp)==IDM_EXIT_TRAY){DestroyWindow(w);return 0;}break;
    case WM_TRAYICON:
      if(lp==WM_LBUTTONDBLCLK){ShowWindow(w,SW_RESTORE);SetForegroundWindow(w);}
      else if(lp==WM_RBUTTONUP||lp==WM_CONTEXTMENU)show_tray_menu();return 0;
    case WM_TIMER:
      if(wp==TIMER_CHILD&&g_child&&WaitForSingleObject(g_child,0)==WAIT_OBJECT_0){
        KillTimer(w,TIMER_CHILD);MessageBoxW(w,L"Połączenie z serwerem zostało zakończone.",APP_TITLE,MB_OK|MB_ICONWARNING);DestroyWindow(w);}return 0;
    case WM_PAINT:{
      PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);RECT c;GetClientRect(w,&c);HBRUSH b=CreateSolidBrush(RGB(0,0,0));FillRect(dc,&c,b);DeleteObject(b);
      if(g_logo){HDC mem=CreateCompatibleDC(dc);HBITMAP old=(HBITMAP)SelectObject(mem,g_logo);BitBlt(dc,0,0,450,90,mem,0,0,SRCCOPY);SelectObject(mem,old);DeleteDC(mem);}
      RECT r={0,95,450,195};HFONT old=(HFONT)SelectObject(dc,g_font_id);SetTextColor(dc,RGB(255,255,255));SetBkMode(dc,TRANSPARENT);
      DrawTextW(dc,g_id[0]?g_id:L"------",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);SelectObject(dc,old);EndPaint(w,&ps);return 0;}
    case WM_CLOSE:
      if(g_persistent){ShowWindow(w,SW_HIDE);return 0;}
      if(MessageBoxW(w,L"Czy na pewno chcesz zakończyć sesję Pomocy Zdalnej?",APP_TITLE,MB_YESNO|MB_ICONQUESTION)==IDYES)DestroyWindow(w);return 0;
    case WM_DESTROY:
      remove_tray_icon();if(!g_persistent){stop_support();cleanup_files();}
      if(g_logo){DeleteObject(g_logo);g_logo=NULL;}PostQuitMessage(0);return 0;}
    return DefWindowProcW(w,msg,wp,lp);
}

int WINAPI WinMain(HINSTANCE inst,HINSTANCE prev,LPSTR cmdline,int show) {
    (void)prev;(void)cmdline;int argc=0;LPWSTR *argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(argc>=2&&lstrcmpiW(argv[1],L"--install-service")==0){int r=(argc==3&&lstrlenW(argv[2])==6)?install_persistent(argv[2]):8;LocalFree(argv);return r;}
    if(argc>=2&&lstrcmpiW(argv[1],L"--remove-service")==0){int r=remove_persistent();LocalFree(argv);return r;}
    g_tray_mode=argc>=2&&lstrcmpiW(argv[1],L"--tray")==0;LocalFree(argv);
    g_persistent=service_exists()&&read_fixed_id();
    HANDLE mutex=CreateMutexW(NULL,TRUE,g_persistent?L"Local\\RolasPomocTray":L"Local\\RolasPomocSingleInstance");
    if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS){if(mutex)CloseHandle(mutex);return 0;}
    g_font_id=CreateFontW(67,0,0,0,800,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Arial Black");
    g_font_ui=CreateFontW(18,0,0,0,600,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    WNDCLASSEXW cls={0};cls.cbSize=sizeof(cls);cls.lpfnWndProc=window_proc;cls.hInstance=inst;g_icon=LoadIconW(inst,MAKEINTRESOURCEW(IDI_APP));
    cls.hIcon=g_icon;cls.hIconSm=g_icon;cls.hCursor=LoadCursorW(NULL,MAKEINTRESOURCEW(32512));cls.lpszClassName=L"RolasPomocWindow";
    if(!RegisterClassExW(&cls))return 1;RECT d={0,0,450,250};AdjustWindowRect(&d,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,FALSE);
    HWND w=CreateWindowExW(WS_EX_TOPMOST,cls.lpszClassName,APP_TITLE,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
      CW_USEDEFAULT,CW_USEDEFAULT,d.right-d.left,d.bottom-d.top,NULL,NULL,inst,NULL);if(!w)return 1;
    if(!g_tray_mode)ShowWindow(w,show);UpdateWindow(w);
    MSG m;while(GetMessageW(&m,NULL,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}
    DeleteObject(g_font_id);DeleteObject(g_font_ui);CloseHandle(mutex);return (int)m.wParam;
}
