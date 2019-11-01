# AdminShare

A file sharing service with administrative focus.

Currently with Linux Server and Linux/Windows clients programs.

## Server
Runs using systemd but can be ran as a standalone executable.
Compile with:
```<pre>
<b>gcc -W -o server adminShareServer.c -lpthread</b></pre>
```

Uses config file at default location:
```<pre>
<b>/usr/local/bin/adminShare.config</b></pre>
```

Place the adminShareServer.service file in:
```<pre>
<b>/etc/systemd/system/</b></pre>
```

Lastly, place the server executable in:
```<pre>
<b>/usr/local/bin/</b></pre>
```

# Config File
The following is how the initial section of the config file should be setup:
```<pre>
<b>Port=</b><i>port number</i>
<b>ServerPassword=</b><i>password for server</i>
<b>Logging=</b><i>Logging level. Currently 1 for on, 0 for off</i>
<b>MaxAttempts=</b><i>Number of attempts for server authentication before ban</i>
<b>Timeout=</b><i>Client timeout in HH:MM:SS</i>
<b>Blocked=</b><i>Comma-separated list of IP addresses to be blocked from the server</i></pre>
```
Following this is a section of shareable directories/files that allow for repeated iterations of the following format:
```<pre>
[Directory/File location]
<b>password=</b><i>directory password</i>
<b>IP=</b><i>Comma-separated list of WHITELISTED IP addresses that can access this item with R/W/D access level as first character. Ex.D192.168.0.1</i>
<b>Expiration=</b><i>Time that Directory/File will no longer be available in: YYYY:MM:DD HH:MM</i></pre>
```

## Linux Client

The program takes no arguments to run.
Compile with:
```<pre>
<b>gcc -W -o <name> adminShareClient.c</b></pre>
```

## Windows Client

Uses .NET Framework Version 4.6.1

## Client Commands

Currently, the commands available to clients are as follows:

Command | Description
------- | ------------
**GET x** | Attempts to retrieve a file from the server currently listed.
**SEND x** | Attempts to send a file to the current directory the client is working in. Cannot be done in the main listing of directories.
**USE x** | Attempts to move to directory 'x' and make that the client's current working directory
**DEL x** | Attempts to delete a file from the server
**exit** | Exits the server
