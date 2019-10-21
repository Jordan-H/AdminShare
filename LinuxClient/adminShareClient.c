#include "adminShareClient.h"

#define BUFLEN 1024

/*    AdminShare Linux Client Program
*     Author: Jordan Hamade
*
*     This program is the Linux Client application to the corresponding AdminShare Server application.
*
*     To compile: gcc -W -o client adminShareClient.c
*/

//Function prototypes
int initiateServer(int, struct AES_ctx*,struct AES_ctx*, int*, int*);
int sessionTimeoutSetup(int, struct AES_ctx*, int*);
void sendFile(char*, int, struct AES_ctx*, int*, struct AES_ctx*, int*);
void getFile(char*, int, struct AES_ctx*, int*, struct AES_ctx*, int*);
void useDirectory(char*, int, struct AES_ctx*, int*, struct AES_ctx*, int*);
void deleteFile(char*, int, struct AES_ctx*, int*, struct AES_ctx*, int*);
void timeoutOccured(int);
int decryptStatus(struct AES_ctx*, uint8_t*, int);
int serverValidated(int, struct AES_ctx*, int*, struct AES_ctx*, int*);
uint8_t* encryptData(struct AES_ctx*, char*, int);
uint8_t* decryptData(struct AES_ctx*, uint8_t*, int);
uint8_t* encryptSize(struct AES_ctx*, int, int);
//Global variables for signal purposes
int encryptCounter = 0;
int decryptCounter = 0;
struct AES_ctx ctx;
struct AES_ctx ctxd;
int sd;

int main(int argc, char **argv){
    int i;
    int n, bytes_to_read = BUFLEN;
    struct hostent *hp;
    struct sockaddr_in server;
    char *bp, buf[BUFLEN];
    int port = 8005; //Temporary test port
    char host[BUFLEN]; //Temporary test IP
    char stringPort[BUFLEN];
    int numItems;
    char inBuf[BUFLEN];
    char *command;
    char sendCommand[BUFLEN];
    char filePath[BUFLEN];
    char *fileName;
    char outBuf[BUFLEN];
    FILE *fp;
    int length;
    char option[1024];
    uint8_t encryptedBuf[1024];
    uint8_t encryptedSize[64];
    char keyRaw[] = "---SAMPLE_KEY---";
    char keydRaw[] = "---SAMPLE_IV----";
    uint8_t *key, *keyD;
    int timeoutLength;
    //Encryption setup
    key = (uint8_t*) keyRaw;
    keyD = (uint8_t*) keydRaw;

    AES_init_ctx(&ctx, keyRaw);
    AES_init_ctx(&ctxd, keyD);

    //Validation
    while(1){
      printf("Server IP:");
      fgets(host, BUFLEN, stdin);

      printf("Server Port:");
      fgets(stringPort, BUFLEN, stdin);
      if((host[0] != '\n') && (stringPort[0] != '\n')){
        break;
      }else{
        printf("Please enter a valid IP address and Port\n");
      }
    }


    host[strlen(host) - 1] = '\0';
    stringPort[strlen(stringPort) - 1] = '\0';
    port = atoi(stringPort);

    if(port == 0){
      fprintf(stderr, "Invalid port number\n");
      exit(1);
    }

    //Connection setup
    bzero((char*)&server, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if((hp = gethostbyname(host)) == NULL){
        fprintf(stderr, "Invalid Host IP\n");
        exit(1);
    }

    bcopy(hp->h_addr, (char*)&server.sin_addr, hp->h_length);

    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("Cannot create socket");
        exit(1);
    }

    if(connect(sd, (struct sockaddr*)&server, sizeof(server)) == -1){
        perror("Connect");
        exit(1);
    }

    bp = buf;

    //Server startup
    if(!initiateServer(sd, &ctx, &ctxd, &encryptCounter, &decryptCounter)){
        close(sd);
        return 0;
    }

    timeoutLength = sessionTimeoutSetup(sd, &ctxd, &decryptCounter);
    signal(SIGALRM, timeoutOccured);

    while((n = recv(sd, encryptedSize, bytes_to_read, 0)) < 64);

    numItems = decryptStatus(&ctxd, encryptedSize, decryptCounter++);
    printf("Main Directory Listings:\n");
    for(i = 0; i < numItems; i++){
        memset(encryptedSize, 0, sizeof(encryptedSize));
        while((n = recv(sd, encryptedSize, 64, 0)) < 64);
        length = decryptStatus(&ctxd, encryptedSize, decryptCounter++);
        while((n = recv(sd, encryptedBuf, 1024, 0)) < 1024){
            printf("n:%d\n", n);
        }
        strncpy(option, decryptData(&ctxd, encryptedBuf, decryptCounter++), length);
        if(option[0] == 'd'){
          printf("%d ---- [D] %s\n", i, option + 1);
        }else if(option[0] == 'f'){
          printf("%d ---- [F] %s\n", i, option + 1);
        }
        memset(encryptedBuf, 0, strlen(encryptedBuf));
        memset(option, 0 ,strlen(option));
    }

    //Main command Loop
    while(1){
        memset(inBuf, 0, sizeof(inBuf));
        alarm(timeoutLength);
        printf("Command: ");
        fgets(inBuf, BUFLEN, stdin);
        alarm(0);
        length = (int)(strlen(inBuf) - 1);
        inBuf[length] = 0;
        send(sd, encryptSize(&ctx, length, encryptCounter++), 64, 0);

        strncpy(sendCommand, inBuf, length);
        send(sd, encryptData(&ctx, sendCommand, encryptCounter++), BUFLEN, 0);
        if(strcmp(inBuf, "exit") == 0){
          break;
        }
        if((command = strtok(inBuf, " ")) != NULL){
            //GET file commmand
            if(strcmp(command, "GET") == 0){
                command = strtok(NULL, " ");
                getFile(command, sd, &ctx, &encryptCounter, &ctxd, &decryptCounter);
                printf("GET command complete!\n");
            }else if(strcmp(command, "USE") == 0){
                //USE file command (For file directories)
                command = strtok(NULL, " ");
                useDirectory(command, sd, &ctx, &encryptCounter, &ctxd, &decryptCounter);
                printf("USE command complete!\n");
            }else if(strcmp(command, "SEND") == 0){
              //SEND file command
              command = strtok(NULL, " ");
              sendFile(command, sd, &ctx, &encryptCounter, &ctxd, &decryptCounter);
              printf("SEND command complete!\n");
            }else if(strcmp(command, "DEL") == 0){
              //DELETE file command
              command = strtok(NULL, " ");
              deleteFile(command, sd, &ctx, &encryptCounter, &ctxd, &decryptCounter);
              printf("DELETE command complete!\n");
            }else{
              printf("Invalid command given\n");
            }
        }
    }
    close(sd);
}

/*
*     Handles the client's initial connection to the server including server authentication
*/
int initiateServer(int sd, struct AES_ctx *ctx, struct AES_ctx *ctxd, int* encryptCounter, int* decryptCounter){
    int i, n;
    uint8_t ciphertext[1024];
    uint8_t cipherCode[64];
    uint8_t ciphertextLen[64];
    int maxAttempts;
    char inBuf[BUFLEN];
    char sendData[BUFLEN];
    int responseCode;

    while((n = recv(sd, &cipherCode, 64, 0)) < 64){
        printf("n:%d\n", n);
    }
    maxAttempts = decryptStatus(ctxd, cipherCode, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;
    memset(cipherCode, 0, sizeof(cipherCode));
    if(maxAttempts == -2){
      fprintf(stderr, "Blocked for exceeding max login attempts.\n");
      return 0;
    }
    if(maxAttempts == -3){
      fprintf(stderr, "Blocked by the server.\n");
      return 0;
    }
    printf("Max Attempts:%d\n", maxAttempts);
    if(maxAttempts != -1){
      //Handle password authentication
        for(i = 0; i < maxAttempts; i++){
            memset(inBuf,0, strlen(inBuf));
            memset(sendData, 0, strlen(sendData));
            printf("Password: ");
            fgets(inBuf, BUFLEN, stdin);
            send(sd, encryptSize(ctx, strlen(inBuf) - 1, *encryptCounter), 64, 0);
            *encryptCounter = *encryptCounter + 1;
            strncpy(sendData, inBuf, strlen(inBuf) - 1);
            memset(ciphertext, 0, sizeof(ciphertext));
            strcpy(ciphertext, encryptData(ctx, sendData, *encryptCounter));
            *encryptCounter = *encryptCounter + 1;
            send(sd, ciphertext, BUFLEN, 0);
            memset(cipherCode, 0, sizeof(cipherCode));
            while((n = recv(sd, &cipherCode, 64, 0)) < 64){
                printf("n:%d\n", n);
            }
            responseCode = decryptStatus(ctxd, cipherCode, *decryptCounter);
            *decryptCounter = *decryptCounter + 1;
            if(responseCode == 1){
                return 1; //Successful password authentication
            }else if(responseCode == 3){
                printf("Blocked by the server\n");
                return 0;
            }else{
                printf("Incorrect Password\n");
            }
        }
        return 0;
    }
    return 1;
}

/*
*   Sets up the timeout for the client. Once the timeout expires, the client will exit the server automatically
*/
int sessionTimeoutSetup(int sd, struct AES_ctx *ctxd, int* decryptCounter){
    int n, bytes_to_read = 8;
    char *bp, buf[BUFLEN];
    char timeoutRaw[1024];
    int t_hour, t_min, t_sec;
    int t_total = 0;
    uint8_t ciphertext[1024];

    while((n = recv(sd, &ciphertext, sizeof(ciphertext), 0)) < 1024){
        printf("n:%d\n", n);
    }
    strcpy(timeoutRaw, decryptData(ctxd, ciphertext, *decryptCounter));
    *decryptCounter = *decryptCounter + 1;
    if(sscanf(timeoutRaw, "%2d:%2d:%2d", &t_hour, &t_min, &t_sec) == 3){
        t_total = (t_hour * 3600) + (t_min * 60) + (t_sec);
        printf("total timeout in seconds: %d\n", t_total);
    }else{
      t_total = -1;
    }
    return t_total;
}

// Timeout
void timeoutOccured(int s){
  char* exitCommand = "exit";
  send(sd, encryptSize(&ctx, 4, encryptCounter++), 64, 0);
  send(sd, encryptData(&ctx, exitCommand, encryptCounter++), 1024, 0);
  printf("\nTimeout occured. Exiting...\n");
  sleep(1);
  exit(EXIT_SUCCESS);
}

/*
*   Validates any request sent to the server to make sure that the command sent is OK by the server
*   Code List
*   1 - OK
*   2 - Password Required
*   3 - Password Accepted
*   -1 - Error
*   -2 - Invalid Privileges
*/
int serverValidated(int sd, struct AES_ctx *ctx, int* encryptCounter, struct AES_ctx *ctxd, int* decryptCounter){
    int n;
    int statusCode = 0;
    char inBuf[BUFLEN];
    char sendData[BUFLEN];
    uint8_t encryptedCode[64];
    int length;

    while((n = recv(sd, &encryptedCode, sizeof(encryptedCode), 0)) < 64){
      printf("n:%d\n", n);
    }
    statusCode = decryptStatus(ctxd, encryptedCode, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;
    if(statusCode == 1){          //OK
        return 1;
    }else if(statusCode == -1){   //ERROR
      printf("Error occured\n");
        return 0;
    }else if(statusCode == 2){    //Password Required
        memset(inBuf, 0, sizeof(inBuf));
        memset(sendData, 0, sizeof(sendData));
        printf("Directory Password:");
        fgets(inBuf, BUFLEN, stdin);
        strncpy(sendData, inBuf, strlen(inBuf) - 1);
        length = (strlen(sendData));
        send(sd, encryptSize(ctx, length, *encryptCounter), 64, 0);
        *encryptCounter = *encryptCounter + 1;
        send(sd, encryptData(ctx, sendData, *encryptCounter), 1024, 0);
        *encryptCounter = *encryptCounter + 1;
        return serverValidated(sd, ctx, encryptCounter, ctxd, decryptCounter);
    }else if(statusCode == 3){    //Password OK
        printf("Password Accepted\n");
        return 1;
    }else if(statusCode == -2){   //Invalid Privileges
      printf("Invalid Privileges\n");
      return 0;
    }else{                        //Other error occured
      printf("Error\n");
      return 0;
    }
}

/*
*   Command that attempts to retrieve a file from the server
*/
void getFile(char* filepath, int serverSD, struct AES_ctx *ctx, int *encryptCounter, struct AES_ctx *ctxd, int *decryptCounter){
    int sd = serverSD;
    int n;
    char* bp;
    char buf[BUFLEN];
    FILE *fp;
    long fileLen;
    int code = -1;
    int bytes_to_read;
    char* fileName;
    uint8_t encryptedSize[64];
    uint8_t encryptedData[1024];
    char decryptedData[1024];

    if(!serverValidated(sd, ctx, encryptCounter, ctxd, decryptCounter)){
        return;
    }
    while((n = recv(sd, encryptedSize, 64, 0)) < 64){
      printf("n:%d\n, n");
    }
    code = decryptStatus(ctxd, encryptedSize, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;
    if(code == 2){ //Access error
      printf("File access error occured on server side.\n");
      return;
    }else if(code != 1){ //Other error
      printf("unknown error\n");
      return;
    }

    memset(encryptedSize, 0, sizeof(encryptedSize));

    while((n = recv(sd, encryptedSize, 64, 0)) < 64){
      printf("n:%d\n", n);
    }
    //Get file info
    fileLen = decryptStatus(ctxd, encryptedSize, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;
    printf("File Length: %ld\n", fileLen);

    fileName = basename(filepath);
    fp = fopen(fileName, "wb");

    bp = buf;

    //Receieve file
    while(fileLen > 0){
        memset(buf, 0, sizeof(buf));
        memset(encryptedData, 0, sizeof(encryptedData));
        if(fileLen < 1024){
            bytes_to_read = (int)fileLen;
        }else{
            bytes_to_read = BUFLEN;
        }
        while((n = recv(sd, encryptedData, 1024, 0)) < 1024){
          bp += n;
          bytes_to_read -= n;
        }
        fileLen -= BUFLEN;
        if(fileLen < 0){
          fileLen = 0;
        }
        printf("Remaining data:%d\n", fileLen);
        fwrite(decryptData(ctxd, encryptedData, *decryptCounter), bytes_to_read, 1, fp);
        *decryptCounter = *decryptCounter + 1;
    }
    fclose(fp);

}

/*
*   Command that attempts to send a file to the server
*/
void sendFile(char* filePath, int serverSD, struct AES_ctx *ctx, int *encryptCounter, struct AES_ctx *ctxd, int *decryptCounter){
  int sd = serverSD;
  int n;
  char* bp;
  char buf[BUFLEN];
  FILE *fp;
  long fileLen;
  int code = -1;
  int bytes_to_read = 1024;
  uint8_t encryptedSize[64];
  uint8_t encryptedData[1024];
  struct stat st_buf;
  int status;
  char cwd[1024];

  if(!serverValidated(sd, ctx, encryptCounter, ctxd, decryptCounter)){
      return;
  }

  //Get file size
  if(getcwd(cwd, sizeof(cwd)) == NULL){
    perror("Error getting path\n");
  }
  strcat(cwd, "/");
  strcat(cwd, filePath);
  status = stat(cwd, &st_buf);

  //Check if file is directory or file
  if(S_ISDIR(st_buf.st_mode)){
    send(sd, encryptSize(ctx, -1, *encryptCounter), 64, 0);
    *encryptCounter = *encryptCounter + 1;
    printf("ERROR: Attempted to send directory.\n");
    return;
  }

  fp = fopen(filePath, "rb");
  fseek(fp, 0, SEEK_END);
  fileLen = ftell(fp);
  printf("file len:%ld\n", fileLen);
  rewind(fp);
  if(fileLen < 1024){
    bytes_to_read = fileLen;
  }

  //Send file size
  send(sd, encryptSize(ctx, fileLen, *encryptCounter), 64, 0);
  *encryptCounter = *encryptCounter + 1;


  //send file
  while(fileLen > 0){
      memset(encryptedData, 0, sizeof(encryptedData));
      memset(buf, 0, sizeof(buf));
      if(bytes_to_read < BUFLEN){
          bytes_to_read = (int)fileLen;
      }
      fread(encryptedData, bytes_to_read, 1, fp);
      send(sd, encryptData(ctx, encryptedData, *encryptCounter), 1024, 0);
      *encryptCounter = *encryptCounter + 1;
      fileLen -= bytes_to_read;
      if(fileLen < 0){
        fileLen = 0;
      }
      printf("Remaining data to be sent:%d\n", fileLen);
  }
  fclose(fp);
}

/*
*   Command that attempts to modify the client's current working directory on the server application
*/
void useDirectory(char* directory, int serverSD, struct AES_ctx *ctx, int *encryptCounter, struct AES_ctx *ctxd, int* decryptCounter){
    int sd = serverSD;
    int statusCode = 0;
    int n, i;
    int fileCount = 0;
    char buf[BUFLEN];
    char *bp;
    int bytes_to_read = BUFLEN;
    uint8_t encryptedSize[64];
    uint8_t encryptedData[1024];
    char fileName[1024];
    uint8_t fileSize[64];
    int fileLen;

    if(!serverValidated(sd, ctx, encryptCounter, ctxd, decryptCounter)){
      printf("Failed server validation\n");
      return;
    }

    while((n = recv(sd, encryptedSize, 64, 0)) < 64){
      printf("n:%d\n, n");
    }
    statusCode = decryptStatus(ctxd, encryptedSize, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;

    if(statusCode == 2){
        printf("Error occured\n");
        return;
    }else if(statusCode != 1){
        printf("Undefined error occured\n");
        return;
    }
    memset(encryptedSize, 0, sizeof(encryptedSize));

    while((n = recv(sd, encryptedSize, 64, 0)) < 64){
      printf("n:%d\n, n");
    }
    fileCount = decryptStatus(ctxd, encryptedSize, *decryptCounter);
    *decryptCounter = *decryptCounter + 1;

    //Reprint new listings for new current working directory
    printf("Listings for: %s\n", directory);
    for(i = 0; i < fileCount; i++){
        memset(buf, 0, sizeof(buf));
        memset(fileName, 0, sizeof(fileName));
        n = 0;
        bp = buf;
        bytes_to_read = BUFLEN;
        while((n = recv(sd, &fileSize, 64, 0)) < 64){
          bp += n;
          bytes_to_read -= n;
        }

        while((n = recv(sd, encryptedData, 1024, 0)) < 1024){
          bp += n;
          bytes_to_read -= n;
        }

        fileLen = decryptStatus(ctxd, fileSize, *decryptCounter);
        *decryptCounter = *decryptCounter + 1;

        strncpy(fileName, decryptData(ctxd, encryptedData, *decryptCounter), fileLen);
        *decryptCounter = *decryptCounter + 1;
        printf("%d ----", i);
        if(fileName[0] == 'f'){
          printf("[F] ");
        }else if(fileName[0] == 'd'){
          printf("[D] ");
        }
        printf("%s\n", fileName + 1);
    }
}

/*
*   Command that attempts to delete a file on the server
*   Codes:
*   1 - Successful deletion
*   2 - File not found
*   3 - Invalid permissions
*/
void deleteFile(char *fileName, int serverSD, struct AES_ctx *ctx, int *encryptCounter, struct AES_ctx *ctxd, int *decryptCounter){
  int sd = serverSD;
  uint8_t encryptedStatus[64];
  int statusCode;
  int n;

  if(!serverValidated(sd, ctx, encryptCounter, ctxd, decryptCounter)){
      return;
  }

  while((n = recv(sd, encryptedStatus, 64, 0)) < 64){
    printf("n:%d\n, n");
  }
  statusCode = decryptStatus(ctxd, encryptedStatus, *decryptCounter);
  *decryptCounter = *decryptCounter + 1;

  if(statusCode == 1){
    printf("File successfully deleted\n");
  }else if(statusCode == 2){
    printf("File not found on server side.\n");
  }else if(statusCode == 3){
    printf("Insufficient permissions to delete this file\n");
  }else{
    printf("Unknown error occured\n");
  }
  return;

}

//    START OF ENCRYPTION/DECRYPTION FUNCTIONS
int decryptStatus(struct AES_ctx* ctx, uint8_t* ciphertext, int counter){
    struct AES_ctx ctxd = *ctx;
    int ret;
    uint8_t *data;
    char* negativeData;
    char ivRaw[] = "---SAMPLE_IV----";
    uint8_t *iv = (uint8_t*)ivRaw;
    ivRaw[(counter % 16)]++;
    AES_ctx_set_iv(&ctxd, iv);
    data = (uint8_t*)ciphertext;
    AES_CTR_xcrypt_buffer(&ctxd, data, 64);

    ret = atoi(data);
    negativeData = strchr(data, '-');
    if(negativeData != NULL){
      ret = atoi(negativeData);
    }
    return ret;
}
uint8_t* encryptData(struct AES_ctx* ctx, char* plaintext, int counter){
    struct AES_ctx ctxe = *ctx;
    char ivRaw[] = "---SAMPLE_IV----";
    uint8_t *iv = (uint8_t*)ivRaw;
    ivRaw[(counter % 16)]++;
    AES_ctx_set_iv(&ctxe, iv);
    char buf[1024];
    int i;
    uint8_t *data;
    uint8_t* ciphertext = malloc(sizeof(uint8_t)*1024);
    memset(buf, 0, sizeof(buf));

    strcpy(buf, plaintext);
    //padding the data
    for(i = strlen(plaintext); i < 1024; i++){
        buf[i] = '0';
    }
    data = (uint8_t*)buf;

    AES_ctx_set_iv(&ctxe, iv);
    AES_CTR_xcrypt_buffer(&ctxe, data, 1024);

    return data;
}
uint8_t* decryptData(struct AES_ctx* ctx, uint8_t* ciphertext, int counter){
    struct AES_ctx ctxd = *ctx;
    uint8_t *data;
    char ivRaw[] = "---SAMPLE_IV----";
    uint8_t *iv = (uint8_t*)ivRaw;
    ivRaw[(counter % 16)]++;
    AES_ctx_set_iv(&ctxd, iv);
    data = (uint8_t*)ciphertext;
    AES_CTR_xcrypt_buffer(&ctxd, data, 1024);
    return data;
}
uint8_t* encryptSize(struct AES_ctx* ctx, int size, int counter){
    uint8_t* ciphertext;
    uint8_t* data;
    char temp[64];
    char buf[64];
    struct AES_ctx ctxe = *ctx;
    char ivRaw[] = "---SAMPLE_IV----";
    uint8_t *iv = (uint8_t*)ivRaw;
    ivRaw[(counter % 16)]++;
    AES_ctx_set_iv(&ctxe, iv);
    int i, j;

    j = 0;
    sprintf(temp, "%d", size);
    for(i = 0; i < 63; i++){
        if((63 - i) <= ((int)strlen(temp))){
            buf[i] = temp[j];
            j++;
        }else{
            buf[i] = '0';
        }
    }
    buf[63] = '\0';
    data = (uint8_t*)buf;

    AES_CTR_xcrypt_buffer(&ctxe, data, 64);


    return data;
}
