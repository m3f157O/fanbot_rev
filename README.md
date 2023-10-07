# fanbot_rev
Reverse engineering and decompilation of a 2003 sample used by apt30


# dropper

The program repeatedly checks that a specified program is running. If not, the program is downloaded, its file attributes are set to "hidden" and the program is run 

# dkom

If the program is running on specific versions of Windows XP and Vista, it will use ZwOpenSection and ZwMapViewOfFile to manually mount a mapping of the whole kernel image into the process virtual menory. Then, via hardcoded offsets, the program is able to retrieve its own EPROCESS structure, and to unlink itself from the ActiveProcessLinks list, which would hold all the processes visible via normal Windows APIs

