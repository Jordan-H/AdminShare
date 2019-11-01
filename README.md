# AdminShare

A file sharing service with administrative focus.

Currently with Linux Server and Linux/Windows clients programs.

##Server
Runs using systemd but can be ran as a standalone executable.
Compile with:
```
gcc -W -o server adminShareServer.c -lpthread
```

Uses config file at default location:
```
/usr/local/bin/adminShare.config
```

Place the adminShareServer.service file in:
```
/etc/systemd/system/
```

Lastly, place the server executable in:
```
/usr/local/bin/
```

#Config File
The following is how the initial section of the config file should be setup:
```
**Port=**_port number_
**ServerPassword=**_password for server_
**Logging=**_Logging level. Currently 1 for on, 0 for off_
**MaxAttempts=**_Number of attempts for server authentication before ban_
**Timeout=**_Client timeout in HH:MM:SS_
**Blocked=**_Comma-separated list of IP addresses to be blocked from the server_
```
Following this is a section of shareable directories/files that allow for repeated iterations of the following format:
```
[Directory/File location]
**password=**_directory password_
**IP=**_Comma-separated list of WHITELISTED IP addresses that can access this item with R/W/D access level as first character. Ex.D192.168.0.1_
**Expiration=**_Time that Directory/File will no longer be available in: YYYY:MM:DD HH:MM_
```

##Linux Client

The program takes no arguments to run.
Compile with:
```
gcc -W -o <name> adminShareClient.c
```

##Windows Client

Uses .NET Framework Version 4.6.1

##Client Commands

Currently, the commands available to clients are as follows:

Command | Description
------- | ------------
**GET x** | Attempts to retrieve a file from the server currently listed.
**SEND x** | Attempts to send a file to the current directory the client is working in. Cannot be done in the main listing of directories.
**USE x** | Attempts to move to directory 'x' and make that the client's current working directory
**DEL x** | Attempts to delete a file from the server
**exit** | Exits the server
