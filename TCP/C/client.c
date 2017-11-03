#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <ifaddrs.h>

#define SERVER_PORT 21
#define MAXBUF 4096
#define PASVMODE 1
#define PORTMODE 0
struct{
    //for connection
    int conn_fd, data_fd, listen_data_fd;
    int conn_port, data_port;
    struct sockaddr_in conn_addr, data_addr;
    char conn_ip[50], owner_ip[50];
    //for PORT PASV
    int mode;  // 0 port 1 pasv

    char now_filepath[MAXBUF];

    char order[MAXBUF], info[MAXBUF], sentence[MAXBUF], message[MAXBUF];

    int flag;
}client;

int Split(char *source, char *dest1, char *dest2, char limit){
    int len = strlen(source);
    if(len == 0)return -1;
    dest1[0] = dest2[0] = '\0';
    int p;
    for(p = 0; p < len; p++){
        if(source[p] == limit)break;
    }
    strncpy(dest1, source, p);
    dest1[p] = '\0';
    if(p == len){
        for(p = len -1; p >= 0; p--){
            if(dest1[p] == '\n' || dest1[p] == '\r'){
                dest1[p] = '\0';
            }
            else break;
        }
        return 0;
    }
    strncpy(dest2, source+p+1, len-p-1);
    len = len-p-1;
    dest2[len] = '\0';
    for(p = len -1; p >= 0; p--){
        if(dest2[p] == '\n' || dest2[p] == '\r'){
            dest2[p] = '\0';
        }
        else break;
    }
    return 1;
}
//-1 failed listenfd ok
int ListenPort(int port){
    int listen_fd;
    struct sockaddr_in addr;
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        printf("Error socket(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        printf("Error bind(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }

    if (listen(listen_fd, 10) == -1) {
        printf("Error listen(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    return listen_fd;
}
//-1 failed conn_fd ok
int AccpetOutsider(int listenfd){//-1 failed connect_fd ok
    int conn_fd;
    if ((conn_fd = accept(listenfd, NULL, NULL)) == -1) {
        printf("Error accept(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    return conn_fd;
}
//-1 failed conn_fd ok
int ConnectOutsider(char *ip, int port){
    int conn_fd;
    struct sockaddr_in addr;
    if ((conn_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        printf("Error socket(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("Error inet_pton(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    if (connect(conn_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Error connect(): %s(%d)\n", strerror(errno), errno);
        return -1;
    }
    return conn_fd;
}

void SendMessage(char *message, int fd){
    int len = strlen(message);
    send(fd, message, len, 0);
    //printf(message);
}
//return len
int ReceiveMessage(char *message, int fd){
    int len = recv(fd, message, MAXBUF, 0);
    message[len] = '\0';
    return len;
}

void CloseAllfd(){
    close(client.listen_data_fd);
    client.listen_data_fd = -1;
    close(client.data_fd);
    client.data_fd = -1;
}
void GetInput(char *message){
    fgets(message, MAXBUF, stdin);
    int len = strlen(message);
    message[len++]='\r';
    message[len++]='\n';
    message[len] = '\0';
}

//void GetLocalIp(int sock, int *ip)
//{
//    socklen_t addr_size = sizeof(struct sockaddr_in);
//    struct sockaddr_in addr;
//    getsockname(sock, (struct sockaddr *)&addr, &addr_size);
//    int host,i;
//    host = (addr.sin_addr.s_addr);
//    for(i=0; i<4; i++){
//        ip[i] = (host>>i*8)&0xff + '0';
//    }
//}
void GetLocalIp(char *ip){
    //http://blog.csdn.net/langeldep/article/details/8306603
    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    while (ifAddrStruct!=NULL)
    {
        if (ifAddrStruct->ifa_addr->sa_family==AF_INET)
        {   // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr = &((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            strcpy(ip,addressBuffer);
        }
        ifAddrStruct = ifAddrStruct->ifa_next;
    }
}

int Init(){
    srand(time(NULL));
    client.conn_fd = -1;
    client.data_fd = -1;
    client.listen_data_fd = -1;
    client.mode = PORTMODE;
    client.conn_port = SERVER_PORT;
    getcwd(client.now_filepath, MAXBUF);
    strcpy(client.conn_ip, "127.0.0.1");
}

// 0 failed 1 ok
int CheckIP(char *ip){
    int len = strlen(ip);
    int ip_num = 0;
    ip[len++] = '.';
    ip[len] = '\0';
    for(int p = 0; p < len; p++){
        if(ip[p] == '.'){
            if(ip_num > 255 || ip_num < 0){
                return 0;
            }
            else ip_num = 0;
        }
        else if(ip[p] > '9' || ip[p] < '0'){
            return 0;
        }
        else{
            ip_num = ip_num * 10 + (ip[p] - '0');
        }
    }
    len--;
    ip[len] = '\0';
    return 1;
}
// 0 failed 1 ok
int CheckStart(char *sentence, char *start){
    int len = strlen(start);
    if(!strncmp(sentence, start, len))return 1;
    return 0;
}

int Port(char *ans){
    char tmp[50];
    client.data_port = rand()%(65535-20000)+20000;
    int len = strlen(client.owner_ip);
    if(len <= 0)return -1;
    strcpy(ans, "227 =");
    for(int i = 0; i < len; i++){
        if(client.owner_ip[i] == '.')tmp[i] = ',';
        else tmp[i] = client.owner_ip[i];
    }
    tmp[len] = '\0';
    sprintf(ans, "PORT %s,%d,%d\r\n", tmp, client.data_port/256, client.data_port%256);
    return 0;
}
int Pasv(char *sentence){
    if(!CheckStart(sentence, "227"))return -1;
    char index[100], info[100], ip[100];
    Split(sentence, info, index, ' ');
    int port = 0;
    int comma_num = 0, port_flag = 0, ip_num = 0;
    int len = strlen(index), p, j;
    for(p = 0; p < len; p++){
        if(index[p] <= '9' && index[p] >= '0')break;
    }
    for(j = len - 1; j >= 0; j--){
        if(index[j] <= '9' && index[j] >= '0')break;
    }
    index[j+1] = '\0';
    len = strlen(index);
    strcpy(info, index+p);
    len = strlen(info);
    info[len++] = ',';
    info[len] = '\0';
    for(p = 0; p < len; p++){
        if(info[p] == ','){
            comma_num++;
            if(comma_num == 4)ip[p] = '\0';
            else if(comma_num <= 3)ip[p] = '.';
            else port = port * 256 + ip_num;
            if(ip_num > 255 || ip_num < 0){
                port_flag = 1;
                break;
            }
            else ip_num = 0;
        }
        else if(info[p] > '9' || info[p] < '0'){
            port_flag = 1;
            break;
        }
        else{
            ip_num = ip_num * 10 + (info[p] - '0');
            if(comma_num <= 3)ip[p] = info[p];
        }
    }
    if(port_flag == 1 || comma_num != 6)return -1;
    client.data_port = port;
    strcpy(client.conn_ip, ip);
    return 0;
}
// 0 failed 1 ok -1 break;
int CheckABOR(){
    if(!strcmp(client.order, "ABOR")){
        if(client.info[0] == '\0')strcpy(client.sentence, "ABOR\r\n");
        else sprintf(client.sentence, "ABOR %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return -1;
    }
    return 0;
}
int CheckCWD(){
    if(!strcmp(client.order, "CWD")||!strcmp(client.order, "cd")){
        if(client.info[0] == '\0')strcpy(client.sentence, "CWD\r\n");
        else sprintf(client.sentence, "CWD %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckDELE(){
    if(!strcmp(client.order, "DELE")||!strcmp(client.order, "delete")){
        if(client.info[0] == '\0')strcpy(client.sentence, "DELE\r\n");
        else sprintf(client.sentence, "DELE %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckLIST(){
    if(!strcmp(client.order, "LIST")||!strcmp(client.order, "ls")) {
        if (client.mode == PASVMODE) {
            SendMessage("PASV\r\n", client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(Pasv(client.sentence) < 0){
                printf("wrong address\r\n");
                return client.flag = 1;
            }
            else{
                if(client.info[0] == '\0')strcpy(client.sentence, "LIST\r\n");
                else sprintf(client.sentence, "LIST %s\r\n", client.info);
                SendMessage(client.sentence, client.conn_fd);
                if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
                printf("%s", client.sentence);
                if(!CheckStart(client.sentence, "150")){
                    return client.flag = 1;
                }
                CloseAllfd();
                client.data_fd = ConnectOutsider(client.conn_ip, client.data_port);
            }
        }
        else {
            Port(client.sentence);
            CloseAllfd();
            client.listen_data_fd = ListenPort(client.data_port);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "200")){
                CloseAllfd();
                return client.flag = 1;
            }
            if(client.info[0] == '\0')strcpy(client.sentence, "LIST\r\n");
            else sprintf(client.sentence, "LIST %s\r\n", client.info);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "150")){
                CloseAllfd();
                return client.flag = 1;
            }
            client.data_fd = AccpetOutsider(client.listen_data_fd);
        }
        if(client.data_fd < 0){
            printf("Connection refued\r\n");
            CloseAllfd();
            return client.flag = 1;
        }
        if(ReceiveMessage(client.sentence, client.data_fd)<=0){
            printf("Connection broken\r\n");
            CloseAllfd();
            return client.flag = 1;
        }
        printf("%s", client.sentence);
        CloseAllfd();
        if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
        printf("%s", client.sentence);
        return client.flag = 1;
    }
    return 0;
}
int CheckMKD(){
    if(!strcmp(client.order, "MKD")||!strcmp(client.order, "mkdir")){
        if(client.info[0] == '\0')strcpy(client.sentence, "MKD\r\n");
        else sprintf(client.sentence, "MKD %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckPASS(){
    if(!strcmp(client.order, "PASS")||!strcmp(client.order, "password")){
        if(client.info[0] == '\0')strcpy(client.sentence, "PASS\r\n");
        else sprintf(client.sentence, "PASS %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckPASV(){
    if(!strcmp(client.order, "PASV")||!strcmp(client.order, "passive")){
        if(client.mode == PASVMODE){
            client.mode = PORTMODE;
            printf("passive mode off, active mode on\r\n");
        }
        else{
            client.mode = PASVMODE;
            printf("active mode off, passive mode on\r\n");
        }
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckPORT(){
    if(!strcmp(client.order, "PORT")||!strcmp(client.order, "active")){
        if(client.mode == PORTMODE){
            client.mode = PASVMODE;
            printf("active mode off, passive mode on\r\n");
        }
        else{
            client.mode = PORTMODE;
            printf("passive mode off, active mode on\r\n");
        }
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckPWD(){
    if(!strcmp(client.order, "PWD") || !strcmp(client.order, "getcwd")|| !strcmp(client.order, "pwd")){
        if(client.info[0] == '\0')strcpy(client.sentence, "PWD\r\n");
        else sprintf(client.sentence, "PWD %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckQUIT(){
    if(!strcmp(client.order, "QUIT")||!strcmp(client.order, "quit")){
        if(client.info[0] == '\0')strcpy(client.sentence, "QUIT\r\n");
        else sprintf(client.sentence, "QUIT %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return -1;
    }
    return 0;
}
int CheckRANAME(){
    if(!strcmp(client.order, "RANAME") || !strcmp(client.order, "rename")){
        char tmp1[500], tmp2[500];
        int flag = Split(client.info, tmp1, tmp2, ' ');
        if(tmp1[0] == '\0' || tmp2[0] == '\0'){
            printf("please input: rename oldname newname\r\n");
            return client.flag = 1;
        }
        sprintf(client.sentence, "RNFR %s\r\n", tmp1);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        if(!CheckStart(client.message, "350")){
            printf("%s", client.message);
            return client.flag = 1;
        }
        printf("%s", client.message);
        sprintf(client.sentence, "RNTO %s\r\n", tmp2);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        if(!CheckStart(client.message, "250")){
            printf("%s", client.message);
            return client.flag = 1;
        }
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckRETR(){
    if(!strcmp(client.order, "RETR")||!strcmp(client.order, "get")||!strcmp(client.order, "download")) {
        if (client.mode == PASVMODE) {
            SendMessage("PASV\r\n", client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(Pasv(client.sentence) < 0){
                printf("wrong address\r\n");
                return client.flag = 1;
            }
            else {
                if (client.info[0] == '\0')strcpy(client.sentence, "RETR\r\n");
                else sprintf(client.sentence, "RETR %s\r\n", client.info);
                SendMessage(client.sentence, client.conn_fd);
                if (ReceiveMessage(client.sentence, client.conn_fd) <= 0)return -1;
                printf("%s", client.sentence);
                if (!CheckStart(client.sentence, "150")) {
                    return client.flag = 1;
                }
                CloseAllfd();
                client.data_fd = ConnectOutsider(client.conn_ip, client.data_port);
            }
        }
        else {
            Port(client.sentence);
            CloseAllfd();
            client.listen_data_fd = ListenPort(client.data_port);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "200")){
                CloseAllfd();
                return client.flag = 1;
            }
            if(client.info[0] == '\0')strcpy(client.sentence, "RETR\r\n");
            else sprintf(client.sentence, "RETR %s\r\n", client.info);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "150")){
                CloseAllfd();
                return client.flag = 1;
            }
            client.data_fd = AccpetOutsider(client.listen_data_fd);
        }
        if(client.data_fd < 0){
            CloseAllfd();
            printf("Connection refued\r\n");
            return client.flag = 1;
        }
        FILE *fp = fopen(client.info, "w");
        if(fp == NULL){
            printf("open file error.\r\n");
            CloseAllfd();
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            return -1;
        }
        char file_buffer[MAXBUF];
        int len_buffer = MAXBUF;
        bzero(file_buffer, len_buffer);
        int file_buffer_len = 0;
        while(1){
            file_buffer_len = recv(client.data_fd, file_buffer, MAXBUF, 0);
            if(file_buffer_len == 0)break;
            if(file_buffer_len<0){
                printf("Error recv\r\n");
                remove(client.info);
                fclose(fp);
                CloseAllfd();
                if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
                printf("%s", client.sentence);
                return client.flag = 1;
            }
            len_buffer = fwrite(file_buffer, sizeof(char), file_buffer_len, fp);
            if(len_buffer < file_buffer_len) {
                printf("Error fwrite\r\n");
                remove(client.info);
                fclose(fp);
                CloseAllfd();
                if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
                printf("%s", client.sentence);
                return client.flag = 1;
            }
            bzero(file_buffer, MAXBUF);
        }
        fclose(fp);
        CloseAllfd();
        if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
        printf("%s", client.sentence);
        return client.flag = 1;
    }
    return 0;
}
int CheckRMD(){
    if(!strcmp(client.order, "RMD") || !strcmp(client.order, "rmdir")){
        if(client.info[0] == '\0')strcpy(client.sentence, "RMD\r\n");
        else sprintf(client.sentence, "RMD %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}
int CheckSTOR(){
    if(!strcmp(client.order, "STOR")||!strcmp(client.order, "put")||!strcmp(client.order, "upload")) {
        FILE *fp = fopen(client.info, "r");
        if(fp == NULL){
            printf("open file error.\r\n");
            return client.flag = 1;;
        }
        if (client.mode == PASVMODE) {
            SendMessage("PASV\r\n", client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(Pasv(client.sentence) < 0){
                printf("wrong address\r\n");
                fclose(fp);
                return client.flag = 1;
            }
            else {
                if (client.info[0] == '\0')strcpy(client.sentence, "STOR\r\n");
                else sprintf(client.sentence, "STOR %s\r\n", client.info);
                SendMessage(client.sentence, client.conn_fd);
                if (ReceiveMessage(client.sentence, client.conn_fd) <= 0)return -1;
                printf("%s", client.sentence);
                if (!CheckStart(client.sentence, "150")) {
                    fclose(fp);
                    return client.flag = 1;
                }
                CloseAllfd();
                client.data_fd = ConnectOutsider(client.conn_ip, client.data_port);
            }
        }
        else {
            Port(client.sentence);
            CloseAllfd();
            client.listen_data_fd = ListenPort(client.data_port);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "200")){
                CloseAllfd();
                return client.flag = 1;
            }
            if(client.info[0] == '\0')strcpy(client.sentence, "STOR\r\n");
            else sprintf(client.sentence, "STOR %s\r\n", client.info);
            SendMessage(client.sentence, client.conn_fd);
            if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
            printf("%s", client.sentence);
            if(!CheckStart(client.sentence, "150")){
                CloseAllfd();
                fclose(fp);
                return client.flag = 1;
            }
            client.data_fd = AccpetOutsider(client.listen_data_fd);
        }
        if(client.data_fd < 0){
            CloseAllfd();
            fclose(fp);
            printf("Connection refued\r\n");
            return client.flag = 1;
        }
        char file_buffer[MAXBUF];
        int len_buffer = MAXBUF;
        bzero(file_buffer, len_buffer);
        int file_buffer_len = 0;
        int byte_count = 0;
        while((file_buffer_len = fread(file_buffer, sizeof(char), MAXBUF, fp))>0){
            if(send(client.data_fd, file_buffer, file_buffer_len, 0)<0){
                SendMessage("send file broken\r\n", client.conn_fd);
                printf("Error send\n");
                CloseAllfd();
                fclose(fp);
                return -1;
            }
            byte_count += file_buffer_len;
            bzero(file_buffer, MAXBUF);
        }
        fclose(fp);
        CloseAllfd();
        if(ReceiveMessage(client.sentence, client.conn_fd)<=0)return -1;
        printf("%s", client.sentence);
        return client.flag = 1;
    }
    return 0;
}
int CheckUSER(){
    if(!strcmp(client.order, "USER") || !strcmp(client.order, "user")){
        if(client.info[0] == '\0')strcpy(client.sentence, "USER\r\n");
        else sprintf(client.sentence, "USER %s\r\n", client.info);
        SendMessage(client.sentence, client.conn_fd);
        if(ReceiveMessage(client.message, client.conn_fd)<=0)return -1;
        printf("%s", client.message);
        client.flag = 1;
        return 1;
    }
    return 0;
}

int Login(){
    char sentence[MAXBUF], info[MAXBUF];
    if(ReceiveMessage(sentence, client.conn_fd)<=0)return -1;
    printf("%s", sentence);
    if(!CheckStart(sentence, "220")){
        printf("connect failed\r\n");
        return -1;
    }
    do{//user
        printf("please input username:");
        GetInput(info);
        sprintf(sentence, "USER %s", info);
        SendMessage(sentence, client.conn_fd);
        if(ReceiveMessage(sentence, client.conn_fd)<=0)return -1;
        printf("%s", sentence);
        if(CheckStart(sentence, "331"))break;
    }while(1);
    do{//pass
        printf("please input password:");
        GetInput(info);
        sprintf(sentence, "PASS %s", info);
        SendMessage(sentence, client.conn_fd);
        if(ReceiveMessage(sentence, client.conn_fd)<=0)return -1;
        printf("%s", sentence);
        if(CheckStart(sentence, "230"))break;
    }while(1);
    return 0;
}
int main(int argc, char **argv) {
    Init();
    if(argc > 2){
        if(CheckIP(argv[1]))strcpy(client.conn_ip, argv[1]);
    }
    if(argc > 3){
        int base = 0, len = strlen(argv[2]);
        for(int j = 0; j < len; j++){
            if(argv[2][j] > '9' || argv[2][j] < '0'){
                base  = -1;
                break;
            }
            base = base * 10  + argv[2][j] - '0';
        }
        if(base > 0)client.conn_port = base;
    }
    client.conn_fd = ConnectOutsider(client.conn_ip, client.conn_port);
    if(client.conn_fd < 0)return 0;
    GetLocalIp(client.owner_ip);
    if(Login() < 0)return 0;
    char sentence[MAXBUF];
    while (1){
        client.flag = 0;
        printf("ftp>");
        GetInput(sentence);
        Split(sentence, client.order, client.info, ' ');
        if(CheckABOR() < 0)break;
        if(CheckCWD() < 0)break;
        if(CheckDELE() < 0)break;
        if(CheckLIST() < 0)break;
        if(CheckMKD() < 0)break;
        if(CheckPASS() < 0)break;
        if(CheckPASV() < 0)break;
        if(CheckPORT() < 0)break;
        if(CheckPWD() < 0)break;
        if(CheckQUIT() < 0)break;
        if(CheckRANAME() < 0)break;
        if(CheckRETR() < 0)break;
        if(CheckRMD() < 0)break;
        if(CheckSTOR() < 0)break;
        if(CheckUSER() < 0)break;
        if(!client.flag){
            SendMessage(sentence, client.conn_fd);
            if(ReceiveMessage(sentence, client.conn_fd)<=0)break;
            printf("%s", sentence);
        }
    }
    close(client.conn_fd);
    return 0;
}