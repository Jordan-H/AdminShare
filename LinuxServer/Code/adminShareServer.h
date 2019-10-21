#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include "aes.c"

struct directory{
  char* path;
  char* pass;
  char* whitelist;
  time_t expiration;
};

struct option{
  char* path;
};

struct client_data{
  struct directory* directories;
  int d_size;
  int client_fd;
  char ip[16];
  char *serverPass;
  char *timeout;
  int maxAttempts;
  int logging;
};

struct blocked_list{
  char ip[16];
};
