#include "adminShareServer.h"

/*    AdminShare Linux Server Program
*     Author: Jordan Hamade
*
*     Server program for the AdminShare project.
*     Tested as a systemd service with the use of proper config file.
*     Executable can be ran through the command line or as a service.
*     To compile: gcc -W -o server adminShareServer.c -lpthread
*/

//Function prototypes
#define BUFLEN 1024
void getRequest(char* ,int, char*, struct AES_ctx*, int*);
void sendRequest(char*, int, char*, struct AES_ctx*, int*, struct AES_ctx*, int*);
void deleteRequest(char*, int, char*, struct AES_ctx*, int*);
char* useRequest(char*, int, char*, struct option*, int*, struct AES_ctx*, int*, int*);
int validOption(struct option*, char*, int);
int canAccess(int, struct directory*, int, char*, int, struct AES_ctx*, int*, struct AES_ctx*, int*);
int isWhitelisted(char*, char*);
int hasPermission(struct directory* , int, int, char*, int, char*);
void sendError(int, struct AES_ctx*, int*);
void* connectionThread(void *);
uint8_t* encryptStatus(struct AES_ctx*, int, int);
char* decryptData(struct AES_ctx*, uint8_t*, int);
uint8_t* encryptData(struct AES_ctx*, char*, int);
int decryptSize(struct AES_ctx*, uint8_t**, int);
int logMessage(char*);

char* blocked_IPs[100];


int main(int argc, char **argv){
    int port, client_len;
    int arg = 1;
    int server_fd, client_fd;
    struct sockaddr_in server, client;

    int n, i;
    char* bp, buf[BUFLEN];
    int bytes_to_read = BUFLEN;
    bp = buf;
    char line[256];
    char timeout[10];
    char* token;
    int logging;
    int maxAttempts;
    char* serverPass;
    int Dcounter = 0;
    char* line2;
    int lineDiff = 0;
    int timeoutHour = 0, timeoutMin = 0, timeoutSec = 0;
    int isBlocked = 0;

    struct directory directories[1000];
    struct client_data c_data;

    struct blocked_list blocked[100];
    int bCounter = 1;
    char* logMsg = (char*) malloc(1024);
    char* initial;
    int on = 1;

    //Config file
    FILE* config = fopen("/usr/local/bin/adminShare.config", "r");
    if(config == NULL){
      perror("Error opening config file");
      if(!logMessage("Failed to find config file.\nExiting....\n")){
        perror("log error");
      }
      return 0;
    }

    //Port
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      token = strtok(line, "=");
      if(strcmp(token, "Port") == 0){
        printf("port found\n");
        token = strtok(NULL, "=");
        port = atoi(token);
      }else{
        port = 8005; // Default port
      }
    }

    //Server Password
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      token = strtok(line, "=");
      if(strcmp(token, "ServerPassword") == 0){
        token = strtok(NULL, "=");
        serverPass = (char*) malloc(strlen(token) - 1);
        strncpy(serverPass, token, strlen(token) - 1);
      }else{
        printf("No server password\n");
        serverPass = "";
      }
      c_data.serverPass = (char*) malloc(strlen(serverPass));
      strncpy(c_data.serverPass, serverPass, strlen(serverPass));
    }

    //Logging Level
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      token = strtok(line, "=");
      if(strcmp(token, "Logging") == 0){
        token = strtok(NULL, "=");
        //printf("%s", token);
        logging = atoi(token);
      }else{
        c_data.logging = 0;
        printf("No Logging\n");
        logging = 0;
      }
    }

    //Max number of attempts for server authentication
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      token = strtok(line, "=");
      if(strcmp(token, "MaxAttempts") == 0){
        token = strtok(NULL, "=");
        maxAttempts = atoi(token);
      }else{
        printf("No specified max login attempts\n");
        maxAttempts = -1;
      }
      c_data.maxAttempts = maxAttempts;
    }

    //Timeout info. YYYY:MM:DD HH:MM
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      token = strtok(line, "=");
      if(strcmp(token, "Timeout") == 0){
        token = strtok(NULL, "=");
        memset(timeout, 0, sizeof(timeout));
        strcpy(timeout, token);
        timeout[strlen(timeout) - 1] = 0;
      }else{
        printf("No timeouts\n");
        strcpy(timeout, "-1");
      }
      c_data.timeout = (char*) malloc(strlen(timeout));
      strcpy(c_data.timeout, timeout);
    }

    if(logging){
      c_data.logging = 1;
      if(!logMessage("Logging initiated\n")){
        perror("log error");
      }
    }

    //List of Blocked IP addresses
    memset(line, 0, sizeof(line));
    if(fgets(line, sizeof(line), config) != NULL){
      line2 = malloc(strlen(line) + 1);
      memcpy(line2, line, strlen(line) + 1);
      line2[strlen(line2) - 1] = '\0';
      token = strtok(line, "=");
      lineDiff = strlen(token);
      if(strcmp(token, "Blocked") == 0){
        memset(token, 0 , sizeof(token));
        token = strtok(line2, ",");
        initial = strchr(token, '=');
        memcpy(blocked[0].ip, initial, strlen(initial));
        if(strcmp(initial, "") != 0){
          while(1){
            token = strtok(NULL, ",");
            if(token != NULL){
              //strncpy(blocked[bCounter].ip, token, strlen(token));
              memcpy(blocked[bCounter].ip, token, strlen(token));
              bCounter++;
              if(bCounter >= 100){
                free(line2);
                free(token);
                break;
              }
            }else{
              free(line2);
              free(token);
              break;
            }
          }
        }
      }else{
        printf("No blocked IPs\n");
      }
    }

    //DEBUG Info dump
    printf("Logging:%d\n", logging);
    sprintf(logMsg, "Server Startup Information:\nPort:%d\nMax server login attempts:%d\nClient Timeout:%s\nBlocked IP addresses:", port, maxAttempts, timeout);
    printf("Max Attempts:%d\n", maxAttempts);
    printf("Timeout %s\n", timeout);
    printf("Blocked IPs:");
    for(int k = 0; k < bCounter; k++){
      printf("%s ", blocked[k].ip);
      sprintf(logMsg + strlen(logMsg), "%s\n", blocked[k].ip);
    }
    printf("\n");
    printf("Logging:%s\nsize:%d\n", logMsg, strlen(logMsg));
    printf("started logging\n");
    if(logging && !logMessage(logMsg)){
      perror("No logging");
    }
    printf("Finished logging basic info\n");
    //ENDOF DEBUG
    memset(logMsg, 0, strlen(logMsg));

    //Loop through all directories listed in the config file
    while(1){
      struct directory d = {"", "", "", 0};
      int deYear = 0, deMonth = 0, deDay = 0, deHour = 0, deMin = 0;
      int dState = 0;
      memset(line, 0, sizeof(line));
      if(fgets(line, sizeof(line), config) != NULL){
        if(line[0] ==  '['){
          dState = 1;
        }else{
          dState = 0;
        }
        char* p = line;
        p[strlen(p)-2] = 0;
        p++;
        d.path = (char *) malloc(strlen(p - 1));
        strncpy(d.path, p, strlen(p - 1));
      }else{
        break;
      }
      for(i =0; i < 3; i++){
        //see if the directory we are trying to list exists
        if(access(d.path, F_OK) != 0 && dState == 1){
          printf("%s path not accessible.\n", d.path);
          sprintf(logMsg, "%s directory path is not accessible.\n", d.path);
          if(logging && !logMessage(logMsg)){
            perror("No logging");
          }
          memset(logMsg, 0, strlen(logMsg));
          break;
        }else if(dState == 0){
          break;
        }
        if(fgets(line, sizeof(line), config) != NULL){
          char* configToken;
          configToken = strtok(line, "=");
          if(strcmp(configToken, "password") == 0){
            configToken = strtok(NULL, "=");
            d.pass = (char*) malloc(strlen(configToken) -1);
            strcpy(d.pass, configToken);
            d.pass[strlen(d.pass) - 1] = 0;
            if(strlen(d.pass) == 0){
              sprintf(logMsg, "No directory password for %s\n", d.path);
              if(logging && !logMessage(logMsg)){
                perror("No logging");
              }
              memset(logMsg, 0, strlen(logMsg));
            }
          }else if(strcmp(configToken, "IP") == 0){
            configToken = strtok(NULL, "=");
            d.whitelist = (char*) malloc(strlen(configToken) + 1);
            strcpy(d.whitelist, configToken);
            d.whitelist[strlen(d.whitelist) - 1] = 0;
            printf("Whitelist items:%s\n", d.whitelist);
            if(d.whitelist[0] == '\0'){
              sprintf(logMsg, "All IPs are whitelisted for %s\n", d.path);
            }else{
              sprintf(logMsg, "Whitelisted IPs for %s:%s\n", d.path, d.whitelist);
            }
            if(logging && !logMessage(logMsg)){
              perror("No logging");
            }
            memset(logMsg, 0, strlen(logMsg));
          }else if(strcmp(configToken, "Expiration") == 0){
            configToken = strtok(NULL, "=");
            if(sscanf(configToken, "%4d.%2d.%2d %2d:%2d", &deYear, &deMonth, &deDay, &deHour, &deMin) == 5){
              struct tm dExpiration = {0};
              dExpiration.tm_year = deYear - 1900; //Years since 1900
              dExpiration.tm_mon = deMonth - 1;
              dExpiration.tm_mday = deDay;
              dExpiration.tm_hour = deHour;
              dExpiration.tm_min = deMin;
              dExpiration.tm_isdst = -1;
              if((d.expiration = mktime(&dExpiration)) == (time_t)-1){
                printf("Failed to convert input to time\n");
              }
            }else{
              struct tm dExpiration = {0};
              dExpiration.tm_year = 9999 - 1900; //Years since 1900
              dExpiration.tm_mon = 12 - 1;
              dExpiration.tm_mday = 31;
              dExpiration.tm_hour = 12;
              dExpiration.tm_min = 59;
              dExpiration.tm_isdst = -1;
              if((d.expiration = mktime(&dExpiration)) == (time_t)-1){
                printf("Failed to convert input to time\n");
              }
              printf("Invalid time format given for %s\n", d.path);
              sprintf(logMsg, "Invalid or no expiration time set for %s\n", d.path);
              if(logging && !logMessage(logMsg)){
                perror("No logging");
              }
              memset(logMsg, 0, strlen(logMsg));
            }
          }
        }
      }
      if(access(d.path, F_OK) == 0 && dState == 1){
        directories[Dcounter] = d;
        Dcounter++;
      }
    }

    fclose(config);
    //END OF CONFIG FILE SETUP

    c_data.directories = directories;
    c_data.d_size = Dcounter;

    if(c_data.d_size == 0){
      if(!logMessage("No directories/files to share. Exiting...\n")){
        perror("No logging");
      }
      return 0;
    }
//Socket Connection Setup
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0){
      if(logging && !logMessage("Socket create failed\n")){
        perror("No logging");
      }
      memset(logMsg, 0, strlen(logMsg));
      perror("socket create");
    }

    bzero((char *)&server, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(server_fd, (struct sockaddr*)&server, sizeof(server)) == -1){
      if(logging && !logMessage("Failed to bind name to socket\n")){
        perror("No logging");
      }
      memset(logMsg, 0, strlen(logMsg));
      perror("Can't bind name to socket");
      exit(1);
    }

    client_len = sizeof(client);
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1){
      if(logging && !logMessage("Failed to set socket options\n")){
        perror("No logging");
      }
      memset(logMsg, 0, strlen(logMsg));
      perror("setsockopt");
      exit(1);
    }

    for(i = 0; i < 99; i++){
      blocked_IPs[i] = (char *) malloc(25);
    }



    listen(server_fd, 1000);

//Main loop handling connections and spawning client threads
    while(1)
    {
      isBlocked = 0;
      if((client_fd = accept(server_fd, (struct sockaddr*)&client, &client_len)) == -1){
        if(logging && !logMessage("Failed to accept a client\n")){
          perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        fprintf(stderr, "Can't accept client\n");
        exit(1);
      }
      printf("Getting client data...\n");
      inet_ntop(AF_INET, &client.sin_addr, c_data.ip, INET_ADDRSTRLEN); //GET IP address of client and save it
      printf("Got client data\n");
      //Immediately disconnect any blocked clients due to login attempts
      for(i = 0; i < 99; i++){
        if(strcmp(c_data.ip, blocked_IPs[i]) == 0){
          sprintf(logMsg, "Client %s blocked due to exceeding max login attempts.\n", c_data.ip);
          if(logging && !logMessage(logMsg)){
            perror("No logging");
          }
          memset(logMsg, 0, strlen(logMsg));
          printf("Client %s blocked\n", c_data.ip);
          isBlocked = 1;
          uint8_t *block_key;
          char block_keyRaw[] = "---SAMPLE_KEY---";
          struct AES_ctx block_ctx;
          block_key = (uint8_t *)block_keyRaw;
          AES_init_ctx(&block_ctx, block_key);
          send(client_fd, encryptStatus(&block_ctx, -2, 0), 64, 0);
        }
      }
      //Disconnect clients blocked by config file
      for(i = 0; i < bCounter; i++){
        if(strcmp(blocked[i].ip, c_data.ip) == 0){
          uint8_t *block_key;
          char block_keyRaw[] = "---SAMPLE_KEY---";
          struct AES_ctx block_ctx;
          block_key = (uint8_t *)block_keyRaw;
          AES_init_ctx(&block_ctx, block_key);
          send(client_fd, encryptStatus(&block_ctx, -3, 0), 64, 0);
          sprintf(logMsg, "Client %s blocked by server.\n", c_data.ip);
          if(logging && !logMessage(logMsg)){
            perror("No logging");
          }
          memset(logMsg, 0, strlen(logMsg));
          printf("client at %s blocked\n", c_data.ip);
          close(client_fd);
          isBlocked = 1;
          break;
        }
      }
      //Accepted a client
      if(!isBlocked){
        sprintf(logMsg, "Accepted a client at: %s\n", c_data.ip);
        if(logging && !logMessage(logMsg)){
          perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        printf("Accepted a client: %s\n", c_data.ip);
        c_data.client_fd = client_fd;
        pthread_t thread_id;
        if(pthread_create(&thread_id, NULL, connectionThread, (void*)&c_data) < 0){
          if(logging && !logMessage("Failed to create client thread\n")){
            perror("No logging");
          }
          memset(logMsg, 0, strlen(logMsg));
          perror("Could not create thread");
          exit(1);
        }
      }
    }

    close(server_fd);
    return 0;

}

//Child Thread handling all requests from clients
void* connectionThread(void* data){
  struct client_data c_data = *(struct client_data*) data;
  int sd = c_data.client_fd;
  struct directory* directories = c_data.directories;
  int total_directories = 0;
  int initial_d = 0;
  int n, num_sent = 0;
  char *timeout = c_data.timeout;
  char* bp, buf[BUFLEN];
  char* cwd = "";
  bp = buf;
  int bytes_to_read = BUFLEN;
  int i, j, k;
  int SPcode = 2;
  int okCode = 1;
  DIR *dir;
  struct dirent *ent;
  FILE *requestFile;
  //size_t bytesRead = 1;
  long bytesRead;
  long fileLen;
  char* token;
  struct option options[1000];
  int dirDepth = 0;
  time_t now;
  int permissions = 0;
  char *decryptPass = malloc(sizeof(char) * 1024);
  uint8_t tempEncrypt[64];
  uint8_t tempEncryptData[1024];
  uint8_t tempEncryptLength[64];
  int encryptCounter = 0;
  int decryptCounter = 0;
  int strLength;
  char* command = malloc(sizeof(char) * 1024);
  char* specFile = malloc(sizeof(char) * 1);
  char* logMsg = malloc(sizeof(char) * 1024);
  DIR *specDir;
  char *blacklistedString;
  int pwLength;

  printf("setting up encryption\n");
  //Encryption stuff
  char keyRaw[] = "---SAMPLE_KEY---";
  char ivRaw[] = "---SAMPLE_IV----";
  char keyRawD[] = "---SAMPLE_KEY---";
  char ivRawD[] = "---SAMPLE_IV----";
  uint8_t *key, *keyD;
  uint8_t *iv, *ivD;
  struct AES_ctx ctx;
  struct AES_ctx ctxD;

  key = (uint8_t *)keyRaw;
  iv = (uint8_t *)ivRaw;

  keyD = (uint8_t*) keyRawD;
  ivD = (uint8_t *)ivRawD;

  AES_init_ctx(&ctx, key);
  AES_init_ctx(&ctxD, keyD);
  uint8_t encryptedData[1024];
  uint8_t *tempDecryptLen[64];
  //end of encryption setup

  printf("Encrypting...\n");

  strcpy(tempEncrypt, encryptStatus(&ctx, c_data.maxAttempts, encryptCounter++)); //MUST BE DONE THIS WAY
  send(sd, &tempEncrypt, 64, 0);

  if(strlen(c_data.serverPass) == 0){
    //Handle no server password
    send(sd, encryptStatus(&ctx, -1, encryptCounter++), 64, 0);
  }else{
    //Handle Server Password
    while(1){
      while((n = recv(sd, &tempDecryptLen, 64, 0)) < 64){
        bp += n;
        bytes_to_read -= n;
      }
      pwLength = decryptSize(&ctxD, tempDecryptLen, decryptCounter++);
      while((n = recv(sd, bp, bytes_to_read, 0)) < BUFLEN){
        bp += n;
        bytes_to_read -= n;
      }
      memset(tempEncrypt, 0, sizeof(tempEncrypt));
      memset(decryptPass, 0, strlen(decryptPass));
      strncpy(decryptPass, decryptData(&ctxD, buf, decryptCounter++), pwLength);
      printf("received Password:%s\n", decryptPass);
      if(strcmp(decryptPass, c_data.serverPass) == 0){
        SPcode = 1;
        send(sd, encryptStatus(&ctx, SPcode, encryptCounter++), 64, 0);
        break;
      }
      c_data.maxAttempts -= 1;
      //Failed authentication
      if(c_data.maxAttempts == 0){
        sprintf(logMsg, "Client %s failed server authentication\n", c_data.ip);
        if(c_data.logging && !logMessage(logMsg)){
        perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        printf("Client %s failed server authentication\n", c_data.ip);
        SPcode = 3;
        send(sd, encryptStatus(&ctx, SPcode, encryptCounter++), 64, 0);
        close(sd);
        blacklistedString = malloc(sizeof(char*) * strlen(c_data.ip) + 1);
        strcpy(blacklistedString, c_data.ip);
        for(k = 0; k < 99; k++){
          if(blocked_IPs[k][0] == '\0'){
            strcpy(blocked_IPs[k], blacklistedString);
            return 0;
          }
        }
      }else{
        memset(tempDecryptLen, 0, sizeof(tempDecryptLen));
        memset(buf, 0, strlen(buf));
        send(sd, encryptStatus(&ctx, SPcode, encryptCounter++), 64, 0);
      }
    }
  }


  sprintf(logMsg, "Client %s Successfully authenticated.\n", c_data.ip);
  if(c_data.logging && !logMessage(logMsg)){
  perror("No logging");
  }
  memset(logMsg, 0, strlen(logMsg));

  //Sendover Timeout info to client
  strncpy(buf, timeout, strlen(timeout));
  send(sd, encryptData(&ctx, timeout, encryptCounter++), 1024, 0);

  memset(buf, 0, sizeof(buf));

  now = time(NULL);
  for(i = 0; i < c_data.d_size; i++){
    if((now < directories[i].expiration || directories[i].expiration == 0) && (isWhitelisted(directories[i].whitelist, c_data.ip) >= 1)){
      total_directories++;
    }
  }

  printf("total:%d\n", total_directories);
  initial_d = total_directories;
  send(sd, encryptStatus(&ctx, total_directories, encryptCounter++), 64, 0);

  j = 0;
  usleep(100000); //Sleep for Windows client
  for(i = 0; i < c_data.d_size; i++){
    if((now < directories[i].expiration || directories[i].expiration == 0) && (isWhitelisted(directories[i].whitelist, c_data.ip) >= 1)){
      memset(buf, 0, sizeof(buf));
      memset(specFile, 0, sizeof(specFile));
      memset(tempEncryptLength, 0, sizeof(tempEncryptLength));
      strncpy(buf, directories[i].path, strlen(directories[i].path));
      options[j].path = malloc(strlen(buf) + 1);
      strcpy(options[j].path, buf);
      specFile = (char*) realloc(specFile, strlen(options[j].path) + 1);
      //if option is a file
      if((specDir = opendir(options[j].path)) == NULL){
        strcat(specFile, "f");
      }else{
        strcat(specFile, "d");
        closedir(specDir);
      }
      strcat(specFile, options[j].path);
      printf("Specific file:%s\n", specFile);
      send(sd, encryptStatus(&ctx, strlen(options[j].path) + 1, encryptCounter++), 64, 0);
      j++;
      send(sd, encryptData(&ctx, specFile, encryptCounter++), 1024, 0);
    }
  }

  //Main command handling loop
  while(1){
    n = 0;
    uint8_t* byteReceiver[64];
    memset(byteReceiver, 0, sizeof(byteReceiver));
    printf("encryption Count:%d\n", encryptCounter);
    printf("Decryption Count:%d\n", decryptCounter);
    while((n = recv(sd, &byteReceiver, 64, 0)) < 64){
      bp += n;
      bytes_to_read -= n;
    }
    strLength = decryptSize(&ctx, byteReceiver, decryptCounter++);
    printf("String length:%d\n", strLength);
    n = 0;
    bytes_to_read = BUFLEN;
    memset(buf, 0, sizeof(buf));
    while((n = recv(sd, bp, bytes_to_read, 0)) < BUFLEN){
      bp += n;
      bytes_to_read -= n;
      printf("bp: %s\n", bp);
      printf("n: %d\n", n);
    }
    memset(command, 0, sizeof(command));
    strncpy(command, decryptData(&ctxD, buf, decryptCounter++), strLength);
    command[strLength] = '\0';
    printf("Command: %s\n", command);
    sprintf(logMsg, "Client %s Command:%s\n", c_data.ip, command);
    if(c_data.logging && !logMessage(logMsg)){
      perror("No logging");
    }
    memset(logMsg, 0, strlen(logMsg));
    //EXIT Command
    if(strcmp(command, "exit") == 0){
      printf("client exiting...\n");
      break;
    }
    //Handle the other request types
    token = strtok(command, " ");
    //GET Request
    if(strcmp(token, "GET") == 0){
      token = strtok(NULL, " ");
      permissions = hasPermission(directories,c_data.d_size, dirDepth, token, permissions, c_data.ip);
      if(validOption(options, token, total_directories) && canAccess(sd, directories, c_data.d_size, token, dirDepth, &ctx, &encryptCounter, &ctxD, &decryptCounter) && permissions > 0){
        getRequest(token, sd, cwd, &ctx, &encryptCounter);
      }else{
        sprintf(logMsg, "Client %s failed attempting to access %s\n", c_data.ip, token);
        if(c_data.logging && !logMessage(logMsg)){
          perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        sendError(sd, &ctx, &encryptCounter);
      }
      printf("Get Request Complete!\n");
      //SEND Request
    }else if(strcmp(token, "SEND") == 0){
      token = strtok(NULL, " ");
      if(dirDepth == 0 || permissions < 2){
        sendError(sd, &ctx, &encryptCounter);
      }else{
        sprintf(logMsg, "Client %s failed attempting to send %s.\n", c_data.ip, token);
        if(c_data.logging && !logMessage(logMsg)){
          perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        sendRequest(token, sd, cwd, &ctx, &encryptCounter, &ctxD, &decryptCounter);
      }
      printf("Send Request Complete!\n");
      //USE Request
    }else if(strcmp(token, "USE") == 0){
      token = strtok(NULL, " ");
      permissions = hasPermission(directories,c_data.d_size, dirDepth, token, permissions, c_data.ip);
      printf("permissions:%d\n", permissions);
      printf("Starting validation\n");
      if(validOption(options, token, total_directories) && canAccess(sd, directories, c_data.d_size, token, dirDepth, &ctx, &encryptCounter, &ctxD, &decryptCounter) && permissions > 0){
        cwd = useRequest(token, sd, cwd, options, &dirDepth, &ctx, &encryptCounter, &total_directories);
        printf("new CWD: %s\n", cwd);
        printf("DirDepth:%d\n", dirDepth);
        //Handle going back up to main directory
        if(strcmp(cwd, "") == 0){
          printf("Sending original listings\n");
          send(sd, encryptStatus(&ctx, okCode, encryptCounter++), 64, 0);
          send(sd, encryptStatus(&ctx, initial_d, encryptCounter++), 64, 0);
          memset(options, 0, sizeof(options));
          j = 0;
          for(i = 0; i < c_data.d_size; i++){
            if((now < directories[i].expiration || directories[i].expiration == 0) && (isWhitelisted(directories[i].whitelist, c_data.ip) >= 1)){
              memset(buf, 0, sizeof(buf));
              strncpy(buf, directories[i].path, strlen(directories[i].path));
              options[j].path = malloc(strlen(buf) + 1);
              strcpy(options[j].path, buf);
              printf("%s\n", buf);
              memset(specFile, 0, sizeof(specFile));
              //if option is a file
              if((specDir = opendir(directories[i].path)) == NULL){
                strcat(specFile, "f");
              }else{
                strcat(specFile, "d");
                closedir(specDir);
              }
              strcat(specFile, directories[i].path);
              send(sd, encryptStatus(&ctx, strlen(specFile), encryptCounter++), 64, 0);
              send(sd, encryptData(&ctx, specFile, encryptCounter++), 1024, 0);
              j++;
            }
          }
        }
        if(strcmp(cwd, "..") == 0){
          printf(".. found\n");
          cwd = "";
          printf("memset done\n");
        }
        printf("new directory total:%d\n", total_directories);
      }else{
        sprintf(logMsg, "Client %s failed attempting to access %s\n", c_data.ip, token);
        if(c_data.logging && !logMessage(logMsg)){
          perror("No logging");
        }
        memset(logMsg, 0, strlen(logMsg));
        sendError(sd, &ctx, &encryptCounter);
      }
      //DELETE Request
    }else if(strcmp(token, "DEL") == 0){
      token = strtok(NULL, " ");
      permissions = hasPermission(directories,c_data.d_size, dirDepth, token, permissions, c_data.ip);
      printf("Delete request\n");
      if(dirDepth == 0 || permissions < 2){
        sendError(sd, &ctx, &encryptCounter);
      }else{
        if(validOption(options, token, total_directories) && canAccess(sd, directories, c_data.d_size, token, dirDepth, &ctx, &encryptCounter, &ctxD, &decryptCounter) && permissions > 2 && dirDepth != 0){
        deleteRequest(token, sd, cwd, &ctx, &encryptCounter);
        }else{
          sprintf(logMsg, "Client %s failed attempting to delete %s\n", c_data.ip, token);
          if(c_data.logging && !logMessage(logMsg)){
            perror("No logging");
          }
          memset(logMsg, 0, strlen(logMsg));
          if(permissions <= 2){
            send(sd, encryptStatus(&ctx, 3, encryptCounter++), 64, 0);
          }else{
            sendError(sd, &ctx, &encryptCounter);
          }
        }
      }

      printf("Delete request complete\n");
    }
  }
  sprintf(logMsg, "Client %s Disconnecting\n", c_data.ip);
  if(c_data.logging && !logMessage(logMsg)){
    perror("No logging");
  }
  memset(logMsg, 0, strlen(logMsg));
  printf("Client Disconnected: %s", c_data.ip);
  close(sd);
  return NULL;
}

/*
* Sends a generic error to the client
*/
void sendError(int sd, struct AES_ctx *ctx, int* encryptCounter){
  int code = -1;
  printf("Sending error\n");
  send(sd, encryptStatus(ctx, code, *encryptCounter), 64, 0);
  *encryptCounter = *encryptCounter + 1;
}

/*
* Checks to see if the client has asked for a valid directory/file available to it
*/
int validOption(struct option* options, char* input,int listSize){
  int i;

  for(i = 0; i < listSize; i++){
    printf("%s Compared to %s\n", options[i].path, input);
    if(strcmp(options[i].path, input) == 0){
      printf("Valid option\n");
      return 1;
    }
  }
  printf("Invalid Option\n");
  return 0;
}

/*
* Handles password validation for the requested file/directory if necessary
*/
int canAccess(int sd, struct directory* directories, int dcount, char* toAccess, int dirDepth, struct AES_ctx *ctx, int* encryptCounter, struct AES_ctx *ctxd, int* decryptCounter){
  int i;
  int code;
  char* bp, buf[BUFLEN];
  int bytes_to_read = BUFLEN;
  int n;
  int length;
  uint8_t *pwSize[64];
  char pw[1024];

  bp = buf;

  if(dirDepth > 0){
    code = 1;
    send(sd, encryptStatus(ctx, code, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    return 1;
  }

  printf("Access D:%s\n", toAccess);

  //Check if the toAccess directory is equal to a directory
  for(i = 0; i < dcount; i++){
    printf("Directory check:%s\n", directories[i].path);
    if(strcmp(toAccess, directories[i].path) == 0){
      printf("Directory match found\n");
      if(strcmp(directories[i].pass, "") != 0){
        code = 2;
        memset(buf, 0, strlen(buf));
        memset(pw, 0, strlen(pw));
        send(sd, encryptStatus(ctx, code, *encryptCounter), 64, 0);
        *encryptCounter = *encryptCounter + 1;

        while((n = recv(sd, &pwSize, 64, 0)) < 64){
          bp += n;
          bytes_to_read -= n;
        }

        while((n = recv(sd, bp, bytes_to_read, 0)) < BUFLEN){
          bp += n;
          bytes_to_read -= n;
        }

        length = decryptSize(ctxd, pwSize, *decryptCounter);
        *decryptCounter = *decryptCounter + 1;
        memset(pw, 0, strlen(pw));
        strncpy(pw, decryptData(ctxd, buf, *decryptCounter), length);
        *decryptCounter = *decryptCounter + 1;
        printf("len:%dpw:%s\n",length, pw);
        for(int q = 0; q < length; q++){
          printf("ascii value for %c:%d\n", pw[q], pw[q]);
          printf("ascii value for %c:%d\n", directories[i].pass[q], directories[i].pass[q]);
        }

        printf("len:%ddirectory pass:%s\ncmp:%d\n",strlen(directories[i].pass), directories[i].pass, strcmp(pw, directories[i].pass));
        if(strcmp(pw, directories[i].pass) == 0){
          printf("Passwords match\n");
          code = 1;
          sleep(1);
          send(sd, encryptStatus(ctx, code, *encryptCounter), 64, 0);
          *encryptCounter = *encryptCounter + 1;
          return 1;
        }else{
          printf("Passwords do not match\n");
          return 0;
        }
      }else{
        code = 1;
        send(sd, encryptStatus(ctx, code, *encryptCounter), 64, 0);
        *encryptCounter = *encryptCounter + 1;
        return 1;
      }
    }
    printf("No match\n");
  }
  return 0;
}

/*
* Checks if the client made a request with equal or higher permissions
*/
int isWhitelisted(char* list, char* ip){
  char* copyList;
  char* token;
  char* listIP;
  char soloIP[20];

  copyList = (char *) malloc(strlen(list) + 1);
  memcpy(copyList, list, strlen(list));
  copyList[strlen(list)] = '\0';

  if(strcmp(copyList, "") == 0){
    return 3; //RWD for anyone
  }

  token = strtok(copyList, ",");
  while(token != NULL){
    listIP =(char*) malloc(strlen(token) + 1);
    strcpy(listIP, token);
    memmove(soloIP, listIP+1, strlen(listIP));

    if(strcmp(soloIP, ip) == 0){
      if(listIP[0] == 'R'){
        return 1; // R only
      }else if(listIP[0] == 'W'){
        return 2; // RW
      }else if(listIP[0] == 'D'){
        return 3; //RWD
      }
    }
    token = strtok(NULL, ",");
  }
  return 0;
}

/*
  Checks the permissions for all directories/files available
  0 - no permissions assigned
  1 - Read
  2 - Read/Write
  3 - Read/Write/Delete
*/
int hasPermission(struct directory* directories,int dcount, int dirDepth, char* toAccess, int current, char* ip){
  int i;

  if(dirDepth > 0){
    return current;
  }

  for(i = 0; i < dcount; i++){
    if(strcmp(toAccess, directories[i].path) == 0){
      return isWhitelisted(directories[i].whitelist, ip);
    }
  }

  return 0;
}

/*
* GET request
* Handles a request for a client to receive a file from the server
*/
void getRequest(char *getbp, int getsd, char* cwd, struct AES_ctx *ctx, int* encryptCounter){
  char *bp;
  uint8_t buf[BUFLEN];
  int sd = getsd;
  FILE *requestFile;
  long fileLen;
  long bytesRead;
  int okCode = 1, errorCode = 2;
  struct stat st_buf;
  int status;

  printf("Starting Get Request\n");

  //malloc
  if((bp = malloc(strlen(getbp) + strlen(cwd) + 1)) != NULL){
    bp[0] = '\0'; // Ensure memory is empty
    strcat(bp, cwd);
    strcat(bp, getbp);
  }else{
    //Malloc error
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    return;
  }

  printf("Get request \n");
  printf("bp: %s\n", bp);

  status = stat(bp, &st_buf);

  if(access(bp, F_OK) != -1 && S_ISREG(st_buf.st_mode)){
    //Tell client file exists and no errors w/ permissions
    send(sd, encryptStatus(ctx, okCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;

    requestFile = fopen(bp, "rb");
    fseek(requestFile, 0, SEEK_END);
    fileLen = ftell(requestFile);
    rewind(requestFile);
    printf("file len:%ld\n", fileLen);
    send(sd, encryptStatus(ctx, fileLen, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    bytesRead = fileLen;
    while(bytesRead > 0){
      printf("Reading file...\n");
      memset(buf, 0, sizeof(buf));
      if(bytesRead <= BUFLEN){
        fread(buf, fileLen, 1, requestFile);
        bytesRead = 0;
      }else{
        fread(buf, BUFLEN, 1, requestFile);
        bytesRead -= BUFLEN;
      }
      printf("Bytes read now: %ld\n", bytesRead);
      send(sd, encryptData(ctx, buf, *encryptCounter), 1024, 0);
      *encryptCounter = *encryptCounter + 1;
    }
    fclose(requestFile);
  }else{
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    printf("Error opening file: %s", bp);
  }

}

/*
* SEND request
* Handles a request for a client to send a file to the server
*/
void sendRequest(char* getbp, int getsd, char* cwd, struct AES_ctx *ctx, int* encryptCounter, struct AES_ctx *ctxD, int* decryptCounter){
  char *oldbp = getbp;
  char *bp;
  char buf[BUFLEN];
  char* fileName;
  int sd = getsd;
  FILE *sendFile;
  long fileLen;
  long bytesRead;
  int n;
  int complete = 0;
  int bytes_to_read = BUFLEN;
  int okCode = 1, errorCode = 2;
  uint8_t dataReceiver[1024];
  uint8_t* byteReceiver[64];
  int first = 0;
  char baseName[100];

  printf("Send request \n");

  //malloc
  if((oldbp = malloc(strlen(getbp) + strlen(cwd) + 1)) != NULL){
    oldbp[0] = '\0'; // Ensure memory is empty
    strcat(oldbp, cwd);
    strcat(oldbp, getbp);
  }else{
    //Malloc error
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    return;
  }

  printf("Sending OK\n");
  send(sd, encryptStatus(ctx, okCode, *encryptCounter), 64, 0);
  *encryptCounter = *encryptCounter + 1;

  //get filename from path
  memcpy(baseName, oldbp, strlen(oldbp) + 1);
  fileName = oldbp;
  while(1){
    if(access(fileName, F_OK) != -1){
      sprintf(fileName, "%s%d", baseName, first);
      first++;
    }else{
      break;
    }
  }

  //get file size
  printf("Waiting for file size\n");
  while((n = recv(sd, &byteReceiver, 64, 0)) < 64){
    bp += n;
    bytes_to_read -= n;
  }
  fileLen = decryptSize(ctxD, byteReceiver, *decryptCounter);
  *decryptCounter = *decryptCounter + 1;
  printf("fileLen: %ld\n", fileLen);

  if(fileLen == -1){
    return;
  }

  sendFile = fopen(fileName, "wb");
  while(!complete){
    bp = buf;
    memset(buf, 0, sizeof(buf));
    memset(dataReceiver, 0, sizeof(dataReceiver));
    bytes_to_read = BUFLEN;
    while((n = recv(sd, dataReceiver, 1024, 0)) < 1024){
      bp += n;
      bytes_to_read -= n;
    }
    printf("Received:%s\n", dataReceiver);
    if(fileLen <= 1024){
      complete = 1; // set complete flag
      bytes_to_read = (int)fileLen;
      printf("Last data, %d\n", bytes_to_read);
    }else{
      fileLen -= 1024;
    }

    fwrite(decryptData(ctxD, dataReceiver, *decryptCounter), bytes_to_read, 1, sendFile);
    *decryptCounter = *decryptCounter + 1;
  }
  printf("Closing file...\n");
  fclose(sendFile);

}

/*
* DELETE request
* Handles a request for a client to delete a file on the server
*/
void deleteRequest(char *getbp, int getsd, char* cwd, struct AES_ctx *ctx, int* encryptCounter){
  int ret;
  int sd = getsd;
  int okCode = 1, errorCode = 2;
  char* fileLocation;

  if(strcmp(getbp, "..") == 0){
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    return;
  }

  fileLocation = malloc(strlen(getbp) + strlen(cwd) + 1);
  strcpy(fileLocation, cwd);
  strcat(fileLocation, getbp);
  printf("File Location:%s\n", fileLocation);

  ret = remove(fileLocation);
  if(ret == 0){
    send(sd, encryptStatus(ctx, okCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
  }else{
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
  }
}

/*
* USE request
* Handles a request for a client to modify its current working directory on the server
*/
char* useRequest(char* givenDirectory, int givenSD, char* cwd, struct option options[], int *dirDepth, struct AES_ctx *ctx, int *encryptCounter, int *total_directories){
  int sd = givenSD;
  char* newDirectory;
  int okCode = 1;
  int errorCode = 2;
  DIR *dir;
  DIR *testDir;
  char buf[BUFLEN];
  char* newCWD;
  char* directoryTest = "";
  struct dirent *ent, *count;
  int fileCount = 0;
  int i = 0;
  int cwdLen;
  char* newDCopy;
  size_t tempLen;
  char* specFile = malloc(sizeof(char) * 1);
  DIR *specDir;
  struct stat st_buf;
  int status;

  //handle .. case
  if(strcmp(givenDirectory, "..") == 0){
    *dirDepth = *dirDepth - 1;
    printf("going up a directory\n");
    if(*dirDepth == 0){
      return ""; // empty string for list of available directories
    }
    newDirectory = malloc(strlen(cwd));
    newDirectory = dirname(cwd);
    tempLen = strlen(newDirectory);
    newDirectory[tempLen] = '/';
    newDirectory[tempLen + 1] = '\0';
    newDCopy = malloc(strlen(newDirectory) + 1);
  }else{
    printf("Current Working Directory:%s\n", cwd);
    printf("Attempting to move to:%s\n", givenDirectory);
    cwdLen = strlen(cwd); //IMPORTANT, DO NOT REMOVE
    //malloc
    if((newDirectory = malloc(strlen(givenDirectory) + strlen(cwd) + 1)) != NULL){
      newDirectory[0] = '\0'; // Ensure memory is empty
      strncpy(newDirectory, cwd, cwdLen);
      strcat(newDirectory, givenDirectory);
      newDCopy = malloc(strlen(newDirectory) + 1);
    }else{
      //Malloc error
      send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
      return cwd;
    }
  }
  status = stat(newDirectory, &st_buf);
  //Check if request is made for a regular file
  if(S_ISREG(st_buf.st_mode)){
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    if(strcmp(cwd, "") == 0){
      return "..";
    }else{
      return cwd;
    }
  }

  if((dir = opendir(newDirectory)) != NULL){
    send(sd, encryptStatus(ctx, okCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    *dirDepth = *dirDepth + 1;
    printf("Incremented dirDepth: %d\n", *dirDepth);
    while((count = readdir(dir)) != NULL){
      //hide hidden files
      if(count->d_name[0] != '.'){
        fileCount++;
      }
    }
    fileCount++; //manual for adding .. to go back
    printf("File count:%d\n", fileCount);
    *total_directories = fileCount;
    send(sd, encryptStatus(ctx, fileCount, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    rewinddir(dir);
    memset(options, 0, sizeof(*options));
    memset(buf, 0 , sizeof(buf));
    strncpy(buf, "..", 3);
    options[i].path = malloc(3);
    memcpy(options[i].path, buf, strlen(buf));
    i++;
    send(sd, encryptStatus(ctx, 3, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    memset(specFile, 0, strlen(specFile));
    specFile = (char*) realloc(specFile, strlen(buf) + 1);
    strcat(specFile, "d");
    strcat(specFile, buf);
    printf("specFile:%s\n", specFile);
    send(sd, encryptData(ctx, specFile, *encryptCounter), 1024, 0);
    *encryptCounter = *encryptCounter + 1;
    while((ent = readdir(dir)) != NULL){
      usleep(100000);
      memset(newDCopy, 0, sizeof(newDirectory));
      memcpy(newDCopy, newDirectory, strlen(newDirectory) + 1);
      memset(specFile, 0, sizeof(specFile));
      directoryTest = malloc(strlen(ent->d_name) + strlen(newDCopy) + 1);
      memcpy(directoryTest, ent->d_name, strlen(ent->d_name) + 1);
      directoryTest = strcat(newDCopy, directoryTest);
      if((testDir = opendir(directoryTest)) != NULL && ent->d_name[0] != '.'){
        memset(buf, 0, sizeof(buf));
        strncpy(buf, ent->d_name, strlen(ent->d_name) + 1);
        buf[strlen(ent->d_name)] = '/';
        buf[strlen(ent->d_name) + 1] = '\0';
        options[i].path = (char*)realloc(options[i].path, ((int)strlen(buf) + 1));
        memset(options[i].path, 0, strlen(options[i].path));
        memcpy(options[i].path, buf, strlen(buf));
        i++;
        send(sd, encryptStatus(ctx, strlen(buf) + 1, *encryptCounter), 64, 0);
        *encryptCounter = *encryptCounter + 1;
        specFile = (char*) realloc(specFile, strlen(buf) + 1);
        if((specDir = opendir(buf)) == NULL){
          strcat(specFile, "f");
        }else{
          strcat(specFile, "d");
          closedir(specDir);
        }
        strcat(specFile, buf);
        send(sd, encryptData(ctx, specFile, *encryptCounter), 1024, 0);
        *encryptCounter = *encryptCounter + 1;
      }else if(ent->d_name[0] != '.'){
        memset(buf, 0, sizeof(buf));
        strncpy(buf, ent->d_name, strlen(ent->d_name));
        options[i].path = (char*)realloc(options[i].path, ((int)strlen(buf) + 1));
        memset(options[i].path, 0, strlen(options[i].path));
        memcpy(options[i].path, buf, strlen(buf));
        i++;
        send(sd, encryptStatus(ctx, strlen(buf) + 1, *encryptCounter), 64, 0);
        *encryptCounter = *encryptCounter + 1;
        specFile = (char*) realloc(specFile, strlen(buf) + 1);
        if((specDir = opendir(buf)) == NULL){
          strcat(specFile, "f");
        }else{
          strcat(specFile, "d");
          closedir(specDir);
        }
        strcat(specFile, buf);
        send(sd, encryptData(ctx, specFile, *encryptCounter), 1024, 0);
        *encryptCounter = *encryptCounter + 1;
      }
      memset(directoryTest, 0, sizeof(directoryTest));
    }

    closedir(testDir);
    printf("Completed USE request!\n");
    if(newDirectory[strlen(newDirectory) - 1] != '/'){
      printf("Modifying pathname\n");
      newCWD = malloc(strlen(newDirectory) + 2); //one for new '/' and one for \0
      strncpy(newCWD, newDirectory, strlen(newDirectory));
      newCWD[strlen(newDirectory)] = '/';
      newCWD[strlen(newDirectory) + 1] = '\0';
    }else{
      printf("Not modifying pathname\n");
      newCWD = malloc(strlen(newDirectory));
      strcpy(newCWD, newDirectory);
    }
    return newCWD;
  }else{
    send(sd, encryptStatus(ctx, errorCode, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    return cwd;
  }
}

//START OF ENCRYPTION
uint8_t* encryptStatus(struct AES_ctx* ctx, int status, int counter){
  char *ret = malloc(sizeof(char) * 64);
  char buf[64];
  char temp[64];
  int i, j;
  uint8_t *data;
  struct AES_ctx ctxd = *ctx;
  char ivRaw[] = "zIesgttLxcVs6xXh";
  uint8_t * iv = (uint8_t*) ivRaw;
  ivRaw[(counter % 16)]++;
  AES_ctx_set_iv(&ctxd, iv);

  j = 0;
  sprintf(temp, "%d", status);

  for(i = 0; i < 63; i++){
    if((63 - i) <= ((int)strlen(temp))){
      buf[i] = temp[j];
      j++;
    }else{
      buf[i] = '0';
    }
  }
  buf[63] = '\0';
  data = (uint8_t *)buf;

  AES_CTR_xcrypt_buffer(&ctxd, data, 64);
  return data;

}

uint8_t* encryptData(struct AES_ctx* ctx, char* plaintext, int counter){
  char* ret = malloc(sizeof(char)*1024);
  char buf[1024];
  int i, j;
  uint8_t *data;
  char ivRaw[] = "zIesgttLxcVs6xXh";
  uint8_t *iv = (uint8_t*) ivRaw;
  ivRaw[(counter % 16)]++;
  struct AES_ctx ctxe = *ctx;

  strcpy(buf, plaintext);
  for(i = strlen(plaintext); i < 1024; i++){
    buf[i] = '0';
  }
  data = (uint8_t *)buf;

  AES_ctx_set_iv(&ctxe, iv);
  AES_CTR_xcrypt_buffer(&ctxe, data, 1024);
  return data;
}

int decryptSize(struct AES_ctx* ctx, uint8_t** encrypted, int counter){
  struct AES_ctx ctxd = *ctx;
  int i;
  int ret;
  char* decrypted = malloc(sizeof(char) *64);
  uint8_t *data;
  char ivRaw[] = "zIesgttLxcVs6xXh";
  uint8_t *iv = (uint8_t*) ivRaw;
  char* negativeData;
  ivRaw[(counter % 16)]++;
  AES_ctx_set_iv(&ctxd, iv);
  data = (uint8_t*)encrypted;
  AES_CTR_xcrypt_buffer(&ctxd, data, 64);

  ret = atoi(data);

  negativeData = strchr(data, '-');
  if(negativeData != NULL){
    ret = atoi(negativeData);
  }
  return ret;

}

char* decryptData(struct AES_ctx* ctx, uint8_t* encrypted, int counter){
  struct AES_ctx ctxd = *ctx;
  int i;
  char* ret = malloc(sizeof(char) *1024);
  uint8_t *data;
  char ivRaw[] = "zIesgttLxcVs6xXh";
  uint8_t * iv = (uint8_t*) ivRaw;
  ivRaw[(counter % 16)]++;
  AES_ctx_set_iv(&ctxd, iv);
  data = (uint8_t *)encrypted;

  AES_CTR_xcrypt_buffer(&ctxd, data, 1024);

  return data;
}
//END OF ENCRYPTION SECTION

//Logs a message to the log file (thread safe)
int logMessage(char* msg){
  time_t rawTime;
  struct tm *timeInfo;
  char* timeString = (char*) malloc(1024);
  int res;

  time(&rawTime);
  timeInfo = localtime(&rawTime);
  timeString = asctime(timeInfo);
  timeString[strlen(timeString) - 1] = '\0';

  FILE* logFile = fopen("/var/log/adminShare.log", "a");
  if(logFile == NULL){
    return 0;
  }
  res = flock(fileno(logFile), LOCK_EX);

  while(res != 0){
    res = flock(fileno(logFile), LOCK_EX);
  }

  fprintf(logFile, "[%s] %s", timeString, msg);
  flock(fileno(logFile), LOCK_UN);
  fclose(logFile);
  return 1;
}
