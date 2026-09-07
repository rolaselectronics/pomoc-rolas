// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Rolas Electronics

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>

#include "build_secrets.h"

#define APP_TITLE L"Rolas Electronics Zdalna Pomoc"
#define REPEATER_HOST L"servis.rolas.com.pl"
#define REPEATER_PORT 5500

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

static HWND g_window;
static HANDLE g_child = NULL;
static HANDLE g_job = NULL;
static WCHAR g_session_dir[MAX_PATH];
static WCHAR g_id[7];
static HFONT g_font_id;
static HBITMAP g_logo;

static BOOL write_bytes(const WCHAR *path, const void *data, DWORD size) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(file, data, size, &written, NULL) && written == size;
    FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static BOOL extract_resource(WORD id, const WCHAR *path) {
    HRSRC resource = FindResourceW(NULL, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(10));
    if (!resource) return FALSE;
    HGLOBAL loaded = LoadResource(NULL, resource);
    if (!loaded) return FALSE;
    DWORD size = SizeofResource(NULL, resource);
    const void *data = LockResource(loaded);
    return data && size && write_bytes(path, data, size);
}

static BOOL native_is_64bit(void) {
    BOOL wow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow64) && wow64) return TRUE;
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);
    return info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
           info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
}

static void path_join(WCHAR *out, const WCHAR *dir, const WCHAR *file) {
    wsprintfW(out, L"%s\\%s", dir, file);
}

static BOOL prepare_payload(WCHAR *winvnc_path) {
    WCHAR temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp)) return FALSE;
    wsprintfW(g_session_dir, L"%sRolasPomoc-%lu", temp, GetCurrentProcessId());
    CreateDirectoryW(g_session_dir, NULL);

    WCHAR hooks_path[MAX_PATH], dd_path[MAX_PATH], dsm_path[MAX_PATH];
    WCHAR portable_path[MAX_PATH], ini_path[MAX_PATH];
    path_join(winvnc_path, g_session_dir, L"winvnc.exe");
    path_join(hooks_path, g_session_dir, L"vnchooks.dll");
    path_join(portable_path, g_session_dir, L"ultravnc.portable");
    path_join(ini_path, g_session_dir, L"ultravnc.ini");

    BOOL x64 = native_is_64bit();
    path_join(dd_path, g_session_dir, x64 ? L"ddengine64.dll" : L"ddengine.dll");
    path_join(dsm_path, g_session_dir, x64 ? L"SecureVNCPlugin64.dsm" : L"SecureVNCPlugin.dsm");
    if (!extract_resource(x64 ? IDR_WINVNC_X64 : IDR_WINVNC_X86, winvnc_path)) return FALSE;
    if (!extract_resource(x64 ? IDR_HOOKS_X64 : IDR_HOOKS_X86, hooks_path)) return FALSE;
    if (!extract_resource(x64 ? IDR_DD_X64 : IDR_DD_X86, dd_path)) return FALSE;
    if (!extract_resource(x64 ? IDR_DSM_X64 : IDR_DSM_X86, dsm_path)) return FALSE;
    if (!write_bytes(portable_path, "", 0)) return FALSE;

    char ini[2048];
    int ini_size = snprintf(ini, sizeof(ini),
        "[admin]\r\n"
        "SocketConnect=1\r\n"
        "HTTPConnect=0\r\n"
        "AutoPortSelect=0\r\n"
        "AuthRequired=1\r\n"
        "ReverseAuthRequired=1\r\n"
        "Secure=0\r\n"
        "AllowLoopback=0\r\n"
        "InputsEnabled=1\r\n"
        "LocalInputsDisabled=0\r\n"
        "FileTransferEnabled=1\r\n"
        "FTUserImpersonation=1\r\n"
        "BlankMonitorEnabled=0\r\n"
        "DisableTrayIcon=1\r\n"
        "AllowProperties=0\r\n"
        "AllowEditClients=0\r\n"
        "AllowShutdown=0\r\n"
        "QuerySetting=2\r\n"
        "QueryIfNoLogon=0\r\n"
        "RemoveWallpaper=1\r\n"
        "RemoveEffects=0\r\n"
        "RemoveFontSmoothing=0\r\n"
        "EnableUnicodeInput=1\r\n"
        "UseDSMPlugin=1\r\n"
        "DSMPlugin=%s\r\n"
        "DSMPluginConfig=SecureVNC;0;0x00104001;%s\r\n"
        "DebugMode=0\r\n"
        "[UltraVNC]\r\n"
        "passwd=%s\r\n"
        "passwd2=%s\r\n",
        x64 ? "SecureVNCPlugin64.dsm" : "SecureVNCPlugin.dsm",
        ROLAS_SECUREVNC_PASSPHRASE_B64,
        ROLAS_UVNC_PASSWORD_HEX,
        ROLAS_UVNC_PASSWORD_HEX);
    if (ini_size <= 0 || ini_size >= (int)sizeof(ini)) return FALSE;
    return write_bytes(ini_path, ini, (DWORD)ini_size);
}

static BOOL generate_id(void) {
    HCRYPTPROV provider = 0;
    uint32_t value = 0;
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
    BOOL ok = CryptGenRandom(provider, sizeof(value), (BYTE *)&value);
    CryptReleaseContext(provider, 0);
    if (!ok) return FALSE;
    value = 200000u + (value % 800000u);
    wsprintfW(g_id, L"%06u", value);
    return TRUE;
}

static BOOL start_support(void) {
    WCHAR winvnc[MAX_PATH];
    if (!generate_id() || !prepare_payload(winvnc)) return FALSE;

    WCHAR ini_path[MAX_PATH];
    path_join(ini_path, g_session_dir, L"ultravnc.ini");

    WCHAR command[1024];
    wsprintfW(command,
              L"\"%s\" -config \"%s\" -multi -autoreconnect id:%s -connect %s::%d -run",
              winvnc, ini_path, g_id, REPEATER_HOST, REPEATER_PORT);

    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);

    g_job = CreateJobObjectW(NULL, NULL);
    if (g_job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
        ZeroMemory(&limits, sizeof(limits));
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    }

    BOOL ok = CreateProcessW(winvnc, command, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL,
                             g_session_dir, &startup, &process);
    if (!ok) return FALSE;
    if (g_job && !AssignProcessToJobObject(g_job, process.hProcess)) {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return FALSE;
    }
    g_child = process.hProcess;
    ResumeThread(process.hThread);
    CloseHandle(process.hThread);
    SetTimer(g_window, TIMER_CHILD, 1000, NULL);
    InvalidateRect(g_window, NULL, FALSE);
    UpdateWindow(g_window);
    return TRUE;
}

static void stop_support(void) {
    KillTimer(g_window, TIMER_CHILD);
    if (g_job) {
        CloseHandle(g_job);
        g_job = NULL;
    } else if (g_child) {
        TerminateProcess(g_child, 0);
    }
    if (g_child) {
        WaitForSingleObject(g_child, 3000);
        CloseHandle(g_child);
        g_child = NULL;
    }
}

static void cleanup_files(void) {
    if (!g_session_dir[0]) return;
    WCHAR path[MAX_PATH];
    const WCHAR *files[] = {
        L"winvnc.exe", L"vnchooks.dll", L"ddengine.dll", L"ddengine64.dll",
        L"SecureVNCPlugin.dsm", L"SecureVNCPlugin64.dsm",
        L"ultravnc.ini", L"ultravnc.portable", L"msrc4plugin.dsm.log",
        L"WinVNC.log", NULL
    };
    for (int i = 0; files[i]; ++i) {
        path_join(path, g_session_dir, files[i]);
        DeleteFileW(path);
    }
    RemoveDirectoryW(g_session_dir);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
        case WM_CREATE:
            g_window = window;
            g_logo = (HBITMAP)LoadImageW(((LPCREATESTRUCTW)lparam)->hInstance,
                MAKEINTRESOURCEW(IDB_LOGO), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
            PostMessageW(window, WM_APP + 1, 0, 0);
            return 0;

        case WM_APP + 1:
            if (!start_support()) {
                MessageBoxW(window,
                    L"Nie udało się przygotować połączenia. Uruchom program ponownie lub skontaktuj się z Rolas Electronics.",
                    APP_TITLE, MB_OK | MB_ICONERROR);
                DestroyWindow(window);
            }
            return 0;

        case WM_TIMER:
            if (wparam == TIMER_CHILD && g_child && WaitForSingleObject(g_child, 0) == WAIT_OBJECT_0) {
                KillTimer(window, TIMER_CHILD);
                MessageBoxW(window, L"Połączenie z serwerem zostało zakończone.",
                    APP_TITLE, MB_OK | MB_ICONWARNING);
                DestroyWindow(window);
            }
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT paint;
            HDC dc = BeginPaint(window, &paint);
            RECT client;
            GetClientRect(window, &client);
            HBRUSH background = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(dc, &client, background);
            DeleteObject(background);

            if (g_logo) {
                HDC memory = CreateCompatibleDC(dc);
                HBITMAP old_bitmap = (HBITMAP)SelectObject(memory, g_logo);
                BitBlt(dc, 0, 0, 450, 90, memory, 0, 0, SRCCOPY);
                SelectObject(memory, old_bitmap);
                DeleteDC(memory);
            }

            RECT id_rect = {0, 100, 450, 200};
            HFONT old_font = (HFONT)SelectObject(dc, g_font_id);
            SetTextColor(dc, RGB(255, 255, 255));
            SetBkMode(dc, TRANSPARENT);
            DrawTextW(dc, g_id[0] ? g_id : L"------", -1, &id_rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dc, old_font);
            EndPaint(window, &paint);
            return 0;
        }

        case WM_CLOSE:
            if (MessageBoxW(window, L"Czy na pewno chcesz zakończyć sesję Pomocy Zdalnej?",
                    APP_TITLE, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                DestroyWindow(window);
            }
            return 0;

        case WM_DESTROY:
            stop_support();
            cleanup_files();
            if (g_logo) {
                DeleteObject(g_logo);
                g_logo = NULL;
            }
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show) {
    (void)previous;
    (void)command_line;

    HANDLE mutex = CreateMutexW(NULL, TRUE, L"Local\\RolasPomocSingleInstance");
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Program Pomoc Rolas jest już uruchomiony.", APP_TITLE, MB_OK | MB_ICONINFORMATION);
        if (mutex) CloseHandle(mutex);
        return 0;
    }

    g_font_id = CreateFontW(67, 0, 0, 0, 800, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Arial Black");

    WNDCLASSEXW cls;
    ZeroMemory(&cls, sizeof(cls));
    cls.cbSize = sizeof(cls);
    cls.lpfnWndProc = window_proc;
    cls.hInstance = instance;
    cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP));
    cls.hIconSm = cls.hIcon;
    cls.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    cls.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    cls.lpszClassName = L"RolasPomocWindow";
    if (!RegisterClassExW(&cls)) return 1;

    RECT desired = {0, 0, 450, 200};
    AdjustWindowRect(&desired, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    HWND window = CreateWindowExW(WS_EX_TOPMOST, cls.lpszClassName, APP_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, desired.right - desired.left, desired.bottom - desired.top,
        NULL, NULL, instance, NULL);
    if (!window) return 1;

    ShowWindow(window, show);
    UpdateWindow(window);

    MSG message;
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    DeleteObject(g_font_id);
    CloseHandle(mutex);
    return (int)message.wParam;
}
