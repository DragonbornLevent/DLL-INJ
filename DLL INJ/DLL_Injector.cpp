#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <tchar.h>
#include "resource.h"
#include "commctrl.h"
#include "ManualMap.h"
#ifdef _DEBUG
#include <iostream>
#endif
HWND procList;
HWND pathLbl;
constexpr size_t UPDATE_PROC_LIST = (WM_APP + 100);
constexpr size_t OPEN_FILE_BTN = (WM_APP + 101);
constexpr size_t INJECT_BTN = (WM_APP + 102);
TCHAR dllPath[MAX_PATH]{ 0 };
bool InsetColumn(HWND hwndLV, int id, TCHAR* text, int width) {
    LVCOLUMN col;
    col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    col.fmt = LVCFMT_LEFT;
    col.cx = width;
    col.pszText = text;
    col.iSubItem = id;
    return ListView_InsertColumn(hwndLV, id, &col);
}
bool CreateItem(HWND hwndLV, LPWSTR name, int image, LPARAM data, LPWSTR procID){
    LVITEM item{ 0 };
    item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
    item.pszText = name;
    item.iImage = image;
    item.lParam = data;
    int tmp = ListView_InsertItem(hwndLV, &item);
    if (tmp >= 0) {
        ListView_SetItemText(hwndLV, tmp, 1, procID);
    }
    return tmp;
}
inline DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry)) {
            do {
                if (!wcscmp(procEntry.szExeFile, procName)){
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}
inline void openDll() {
    OPENFILENAME openDlg{};
    openDlg.lStructSize = sizeof(OPENFILENAME);
    openDlg.lpstrFile = dllPath;
    openDlg.nMaxFile = MAX_PATH;
    openDlg.lpstrFilter = TEXT("DLL-File (Internal Cheat)\0*.dll\0All Files\0*.*");
    openDlg.lpstrTitle = TEXT("Open Internal Hack to inject");
    openDlg.Flags = OFN_FILEMUSTEXIST | OFN_FORCESHOWHIDDEN;
    if (GetOpenFileName(&openDlg)) {
        SetWindowText(pathLbl, dllPath);
    }
}
inline void inject() {
    if (!*dllPath) {
        MessageBox(NULL, TEXT("Please select a DLL file to inject first!"), TEXT("No DLL selected!"), MB_OK);
        return;
    }
    LRESULT iSelect{ SendMessage(procList, LVM_GETNEXTITEM, -1, LVNI_FOCUSED) };
    if (iSelect == -1) {
        MessageBox(NULL, TEXT("Please select a process from the process list first!"), TEXT("No Process selected!"), MB_OK);
        return;
    }
    TCHAR ProcIdTxt[7]{ 0 };
    LVITEM procItem{ 0 };
    procItem.mask = LVIF_TEXT;
    procItem.iSubItem = 1;
    procItem.pszText = ProcIdTxt;
    procItem.cchTextMax = 8;
    procItem.iItem = (int)iSelect;
    SendMessage(procList, LVM_GETITEMTEXT, iSelect, (LPARAM)&procItem);
    DWORD procId{ (DWORD)std::stoi(ProcIdTxt) };
#ifdef _DEBUG
    std::cout << "ProcID: " << procId << std::endl;
#endif 
    if (!procId) {
        MessageBox(NULL, TEXT("Something went wrong reading the ProcID!"), TEXT("No ProcId found!"), MB_OK);
        return;
    }
    HANDLE hProc{ OpenProcess(PROCESS_ALL_ACCESS, 0, procId) };
    char charDllName[MAX_PATH];
    for (size_t i{ 0 }; i < MAX_PATH; ++i) {
        charDllName[i] = (char)dllPath[i];
        if (!dllPath[i]) break;
    }
    if (!ManualMap(hProc, charDllName)) {
        MessageBox(NULL, TEXT("Failed to inject the DLL!"), TEXT("Injection Failed!"), MB_OK);
    }
}
inline int refreshProcList() {
    SendMessage(procList, LB_RESETCONTENT, 0, 0);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry; 
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry)) {
            do {
                CreateItem(procList, procEntry.szExeFile, 0, NULL, (LPWSTR) std::to_wstring(procEntry.th32ProcessID).c_str());
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return 0;
}
LRESULT CALLBACK MessageHandler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CLOSE:
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case UPDATE_PROC_LIST:
            refreshProcList();
            break;

        case INJECT_BTN:
            inject();
            break;

        case OPEN_FILE_BTN:
            openDll();
            break;
        }
	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}
int main(){
#ifdef _DEBUG
    ShowWindow(GetConsoleWindow(), SW_SHOW);
#else
    ShowWindow(GetConsoleWindow(), SW_HIDE);
#endif 
    HINSTANCE hInstance = GetModuleHandle(0);
    WNDCLASSEX wc{}; //window struct
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MessageHandler;
    wc.hInstance = hInstance;
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = TEXT("DLL_Injector");
    RegisterClassEx(&wc);
    HWND hWnd{ CreateWindowEx(0, TEXT("DLL_Injector"), TEXT("Manual DLL Injector"), WS_VISIBLE | WS_EX_LAYERED | WS_BORDER, CW_USEDEFAULT, CW_USEDEFAULT, 500, 700, 0, 0, hInstance, 0) };
    procList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, TEXT(""), WS_VISIBLE | WS_BORDER | WS_CHILD | LVS_SINGLESEL | LVS_REPORT | WS_VSCROLL | ES_AUTOHSCROLL, 10, 10, 465, 500, hWnd, NULL, 0, 0);
    HWND updateBtn{ CreateWindowEx(0, TEXT("button"), TEXT("Update Process List"), WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | BS_FLAT, 10, 520, 465, 30, hWnd, (HMENU)UPDATE_PROC_LIST, hInstance, 0) };
    HWND openBtn{ CreateWindowEx(0, TEXT("button"), TEXT("Open"), WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | BS_FLAT, 10, 560, 100, 30, hWnd, (HMENU)OPEN_FILE_BTN, hInstance, 0) };
    pathLbl = CreateWindowEx(0, TEXT("static"), dllPath, WS_TABSTOP | WS_CHILD | WS_VISIBLE, 120, 560, 355, 30, hWnd, NULL, hInstance, 0);
    HWND injectBtn{ CreateWindowEx(0, TEXT("button"), TEXT("INJECT"), WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | BS_FLAT, 10, 600, 465, 50, hWnd, (HMENU)INJECT_BTN, hInstance, 0) };
    SendMessage(procList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
    HICON hicon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
    TCHAR ProcHeader[]{ TEXT("Process") };
    InsetColumn(procList, 0, ProcHeader, 300);
    TCHAR IdHeader[]{ TEXT("ProcID") };
    InsetColumn(procList, 1, IdHeader, 160);
    refreshProcList();
    MSG msg;
    DWORD dwExit{ STILL_ACTIVE };
    while (dwExit == STILL_ACTIVE) {
        BOOL result = GetMessage(&msg, 0, 0, 0);
        if (result > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            return result;
        }
    }
    return 0;
}