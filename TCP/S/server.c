#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <memory.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <pwd.h>
#include<grp.h>
#include <time.h>
#include <sys/time.h>

#define SERVER_PORT 21
#define MAXBUF 4096
#define PASVMODE 1
#define PORTMODE 0
#define NOMODE -1
struct {
    //for connection
    int listen_conn_fd, conn_fd, data_fd, listen_data_fd;
    int conn_port, data_port;
    struct sockaddr_in conn_addr, data_addr;
    char conn_ip[50], owner_ip[50];
    int data_flag;
    //for PORT PASV
    int mode;  // 0 port 1 pasv
    //for USER
    char username[10];
    int user_flag;
    //for PASS
    int pass_flag;
    //for TYPY
    int type_flag;
    //for RNFR RNTO
    char old_name[100];
    int rename_flag;
    //for CWD RMD MKD LIST DELE
    char root_filepath[200];
    char now_filepath[200];
    //for QUIT, ABOR
    int total_byte, total_outsider;
    int time_byte, time_num;
    //for input
    char order[MAXBUF], info[MAXBUF];
}server;
typedef enum
{
    ABOR, CWD, DELE, LIST, MKD, PASS, PASV, PORT, QUIT, PWD,
    RETR, RMD, RNFR, RNTO, STOR, SYST, TYPE, USER
}orders_list;

char orders_name[USER+1][5] = {
        "ABOR", "CWD", "DELE", "LIST", "MKD", "PASS", "PASV", "PORT", "QUIT", "PWD",
        "RETR", "RMD", "RNFR", "RNTO", "STOR", "SYST", "TYPE", "USER"
};

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

void InitTotal(){
    srand(time(NULL));
    strcpy(server.username, "anonymous");
    GetLocalIp(server.owner_ip);
    server.total_byte = 0;
    server.total_outsider = 0;
    server.listen_data_fd = -1;
    server.data_fd = -1;
}

void InitTime(){
    strcpy(server.now_filepath, server.root_filepath);
    server.rename_flag = 0;
    server.user_flag = 0;
    server.pass_flag = 0;
    server.type_flag = 0;
    server.mode = NOMODE;
    server.time_byte = 0;
    server.time_num = 0;
    server.data_flag = 0;
    server.total_outsider ++;
}
//-1 empty source 0 source without limit 1 split ok
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
//-1 unset order else order_list
int SwitchOrder(char *order){
    int len = USER + 1;
    for(int i = 0; i < len; i++){
        if(!strcmp(orders_name[i], order))return i;
    }
    return -1;
}
// -1 failed 0 ok
int CheckFilepath(char *filepath){
    int len = strlen(server.root_filepath);
    if(len <= 0)return -1;
    char tmp1[MAXBUF], tmp2[MAXBUF];
    if(server.info[0] == '/') {
        if(!strncmp(server.info, server.root_filepath, len))return 0;
        else return -1;
    }
    while (1){
        Split(server.info, tmp1, tmp2, '/');
        if(!strcmp(tmp1, "..")){
            chdir("..");
            getcwd(server.info, MAXBUF);
            strcat(server.info, "/");
            strcat(server.info, tmp2);
        }
        else if(!strcmp(tmp1, ".")){
            chdir(".");
            getcwd(server.info, MAXBUF);
            strcat(server.info, "/");
            strcat(server.info, tmp2);
        }
        else break;
    }
    chdir(server.now_filepath);
    if(server.info[0] != '/'){
        sprintf(tmp1,"%s/%s", server.now_filepath, server.info);
        strcpy(server.info, tmp1);
    }
    if(!strncmp(server.info, server.root_filepath, len))return 0;
    else return -1;
}

void SetPort(int *old_port, int new_port){
    *old_port = new_port;
}
// -1 failed 0 ok
int Dele(char *file_name){
    char tmp[200];
    struct stat buf;
    struct dirent* fp;
    DIR* dirfd;
    if(stat(file_name, &buf) < 0){
        return -1;
    }
    if(S_ISREG(buf.st_mode)){
        return remove(file_name);
    }
    else if(S_ISDIR(buf.st_mode)){
        dirfd = opendir(file_name);
        while((fp = readdir(dirfd)) != NULL){
            if(!strcmp(fp -> d_name, "."))continue;
            if(!strcmp(fp -> d_name, ".."))continue;
            sprintf(tmp, "%s/%s", file_name, fp->d_name);
            if(Dele(tmp) < 0){
                return -1;
            }
        }
        closedir(dirfd);
        rmdir(file_name);
    }
    else{
        return -1;
    }
    return 0;
}

void ListFile(struct stat *buf, char *file_name, char *ansline) {
    //http://blog.csdn.net/wqx521/article/details/50755469
    char tmp[MAXBUF] = {"----------"};
    switch(buf->st_mode & S_IFMT)//按位&获取文件基本属性
    {
        case S_IFIFO:
            tmp[0] = 'f';
            break;
        case S_IFDIR:
            tmp[0] = 'd';
            break;
        case S_IFSOCK:
            tmp[0] = 's';
            break;
        case S_IFBLK:
            tmp[0] = 'b';
            break;
        case S_IFLNK:
            tmp[0] = 'l';
            break;
    }

    if(buf->st_mode & S_IRUSR )tmp[1] = 'r';
    if(buf->st_mode & S_IWUSR )tmp[2] = 'w';
    if(buf->st_mode & S_IXUSR )tmp[3] = 'x';
    if(buf->st_mode & S_IRGRP )tmp[4] = 'r';
    if(buf->st_mode & S_IWGRP )tmp[5] = 'w';
    if(buf->st_mode & S_IXGRP )tmp[6] = 'x';
    if(buf->st_mode & S_IROTH )tmp[7] = 'r';
    if(buf->st_mode & S_IWOTH )tmp[8] = 'w';
    if(buf->st_mode & S_IXOTH )tmp[9] = 'x';
    tmp[10] = '\0';
    ansline[0] = '\0';
    strcpy(ansline, tmp);
    sprintf(tmp, "\t%d", (int)buf->st_nlink); //打印链接数
    strcat(ansline, tmp);
    struct passwd *ptr;
    struct group *str;
    ptr = getpwuid(buf->st_uid);
    str = getgrgid(buf->st_gid);
    sprintf(tmp, "\t%s\t%s", ptr ->pw_name, str -> gr_name);
    strcat(ansline, tmp);
    sprintf(tmp, "\t%ld", buf->st_size);
    strcat(ansline, tmp);
    sprintf(tmp, "\t%.12s ", 4 + ctime(&buf->st_mtime));
    strcat(ansline, tmp);
    sprintf(tmp, "\t%s\r\n", file_name); //打印文件名
    strcat(ansline, tmp);
//    int len = strlen(ansline);
//    ansline[len++]='\r';
//    ansline[len++]='\n';
//    ansline[len]='\0';
}
// -1 failed 0 ok
int List(char *file_name, char *ans){
    char tmp[MAXBUF], ansline[MAXBUF];
    int flag = 0;
    struct stat buf;
    struct dirent* fp;
    DIR* dirfd;
    if(stat(file_name, &buf) < -1)return -1;
    if(S_ISREG(buf.st_mode)){
        for(flag = strlen(file_name); flag >= 0; flag--){
            if(file_name[flag] == '/')break;
        }
        strcpy(tmp, file_name+flag+1);
        ListFile(&buf, tmp, ans);
        return 0;
    }
    else if(S_ISDIR(buf.st_mode)){
        ans[0] = '\0';
        dirfd = opendir(file_name);
        while((fp = readdir(dirfd)) != NULL){
            if(!strcmp(fp -> d_name, "."))continue;
            if(!strcmp(fp -> d_name, ".."))continue;
            sprintf(tmp, "%s/%s", file_name, fp->d_name);
            if(stat(tmp, &buf) < -1)return -1;
            ListFile(&buf, fp->d_name, ansline);
            strcat(ans, ansline);
        }
        if(ans[0] == '\0'){
            strcpy(ans, "There is nothing in dir\r\n");
        }
        closedir(dirfd);
        return 0;
    }
    else{
        return -1;
    }
}
// -1 failed 0 ok
int Port(char *info){
    int port = 0;
    char ip[100];
    int comma_num = 0, port_flag = 0, ip_num = 0;
    int len = strlen(info), p;
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
    server.data_port = port;
    strcpy(server.conn_ip, ip);
    return 0;
}
// -1 failed 0 ok
int Pasv(char *ans){
    char tmp[50];
    server.data_port = rand()%(65535-20000)+20000;
    int len = strlen(server.owner_ip);
    if(len <= 0)return -1;
    strcpy(ans, "227 =");
    for(int i = 0; i < len; i++){
        if(server.owner_ip[i] == '.')tmp[i] = ',';
        else tmp[i] = server.owner_ip[i];
    }
    tmp[len] = '\0';
    sprintf(ans, "227 =%s,%d,%d\r\n", tmp, server.data_port/256, server.data_port%256);
    //printf("%s\n", ans);
    return 0;
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
int  ReceiveMessage(char *message, int fd){
    int len = recv(fd, message, MAXBUF, 0);
    message[len] = '\0';
    return len;
}
// -1 failed 0 ok
int InputABOR(){
    char sentence[MAXBUF];
    sprintf(sentence, "221-You have transferred %d bytes in %d files.\r\n\
221-Thank you for using the FTP service on ftp.ssast.org.\r\n\
221 Goodbye.\r\n",server.time_byte, server.time_num);
    SendMessage(sentence, server.conn_fd);
    return 0;
}
int InputCWD(){
    char sentence[MAXBUF];
    if(CheckFilepath(server.info)<0 ||chdir(server.info)<0){
        sprintf(sentence, "550 No such file or directory.\r\n");
        SendMessage(sentence, server.conn_fd);
        return -1;
    }
    else{
        getcwd(server.now_filepath, MAXBUF);
        SendMessage("250 change ok\r\n", server.conn_fd);
        return 0;
    }
}
int InputDELE(){
    //sprintf(sentence, "%s/%s", server.now_filepath, server.info);
    if(CheckFilepath(server.info)<0 || remove(server.info)<0){
        SendMessage("550 remove fail\r\n", server.conn_fd);
        return -1;
    }
    else{
        SendMessage("250 remove ok\r\n", server.conn_fd);
        return 0;
    }
}
int InputLIST(){
    if(server.mode == NOMODE) {
        SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
        return -1;
    }
    SendMessage("150 ready for data connection.\r\n", server.conn_fd);
    if(server.mode == PORTMODE){
        close(server.data_fd);
        server.data_fd = ConnectOutsider(server.conn_ip, server.data_port);
        if(server.data_fd < 0){
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            return -1;
        }
    }
    else if(server.mode == PASVMODE){
        close(server.data_fd);
        server.data_fd = AccpetOutsider(server.listen_data_fd);
        if(server.data_fd < 0){
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            close(server.listen_data_fd);
            server.listen_data_fd = -1;
            return -1;
        }
    }
    server.data_flag = 1;
    char sentence[MAXBUF];
    if(server.info[0] != '\0'){
        //if(server.info[0] != '/')sprintf(sentence, "%s/%s", server.now_filepath, server.info);
        if(CheckFilepath(server.info)<0 || List(server.info, sentence) < 0){
            SendMessage("451 list error\r\n", server.conn_fd);
            if(server.mode == PASVMODE)close(server.listen_data_fd);
            close(server.data_fd);
            server.listen_data_fd = -1;
            server.data_fd = -1;
            server.mode = NOMODE;
            server.data_flag = 0;
            return -1;
        }
    }
    else{
        if(List(server.now_filepath, sentence) < 0){
            SendMessage("451 list error\r\n", server.conn_fd);
            if(server.mode == PASVMODE)close(server.listen_data_fd);
            close(server.data_fd);
            server.listen_data_fd = -1;
            server.data_fd = -1;
            server.mode = NOMODE;
            server.data_flag = 0;
            return -1;
        }
    }
    //printf("%s\n", sentence);
    SendMessage(sentence, server.data_fd);
    SendMessage("226 list ok\r\n", server.conn_fd);
    if(server.mode == PASVMODE)close(server.listen_data_fd);
    close(server.data_fd);
    server.listen_data_fd = -1;
    server.data_fd = -1;
    server.data_flag = 0;
    server.mode = NOMODE;
    return 0;
}
int InputMKD(){
    DIR *dirfd = opendir(server.info);
    if(dirfd == NULL){
        if(CheckFilepath(server.info)<0 ||mkdir(server.info, 0775) < 0){
            SendMessage("550 creat dir error\r\n", server.conn_fd);
            return -1;
        }
        else{
            SendMessage("257 creat dir ok\r\n", server.conn_fd);
            return 0;
        }
    }
    else {
        SendMessage("250 dir exist\r\n", server.conn_fd);
        closedir(dirfd);
        return 0;
    }
}
int InputPASS(){
    if(server.user_flag != 1){
        SendMessage("503  please input USER\r\n", server.conn_fd);
        return -1;
    }
    int len = strlen(server.info);
    for(int i = 0; i < len; i++){
        if(server.info[i] == '@'){
            server.pass_flag = 1;
            server.user_flag = 0;
            SendMessage("230-\r\n\
230-Welcome to\r\n\
230-School of Software\r\n\
230-FTP Archives at ftp.ssast.org\r\n\
230-\r\n\
230-This site is provided as a public service by School of\r\n\
230-Software. Use in violation of any applicable laws is strictly\r\n\
230-prohibited. We make no guarantees, explicit or implicit, about the\r\n\
230-contents of this site. Use at your own risk.\r\n\
230-\r\n\
230 Guest login ok, access restrictions apply.\r\n", server.conn_fd);
            return 0;
        }
    }
    SendMessage("530 wrong password\r\n", server.conn_fd);
    return -1;
}
int InputPASV(){
    char sentence[MAXBUF];
    if(server.info[0] != '\0' || Pasv(sentence) < 0){
        SendMessage("530 wrong set mode\r\n", server.conn_fd);
        return -1;
    }
    else{
        close(server.listen_data_fd);
        server.listen_data_fd = ListenPort(server.data_port);
        if(server.listen_data_fd < 0)return -1;
        server.mode = PASVMODE;
        SendMessage(sentence, server.conn_fd);
        return 0;
    }
}
int InputPORT(){
    if(Port(server.info) < 0){
        SendMessage("530 wrong set mode\r\n", server.conn_fd);
        return -1;
    }
    else{
        server.mode = PORTMODE;
        SendMessage("200 PORT command successful.\r\n", server.conn_fd);
        return 0;
    }
}
int InputPWD(){
    char sentence[MAXBUF];
    if(server.info[0] == '\0'){
        sprintf(sentence, "257 \"%s\"\r\n", server.now_filepath);
        SendMessage(sentence, server.conn_fd);
        return 0;
    }
    else{
        SendMessage("550 PWD must no argument.\r\n", server.conn_fd);
        return -1;
    }
}
int InputQUIT(){
    char message[MAXBUF];
    sprintf(message, "221-You have transferred %d bytes in %d files.\r\n\
221-Thank you for using the FTP service on ftp.ssast.org.\r\n\
221 Goodbye.\r\n",server.time_byte, server.time_num);
    SendMessage(message, server.conn_fd);
    return 0;
}
int InputRETR(){
    struct stat buf;
    FILE *fp = fopen(server.info, "r");
    if(fp == NULL){
        SendMessage("550 file not exist.\r\n", server.conn_fd);
        return -1;
    }
    if(CheckFilepath(server.info) < 0 ||stat(server.info, &buf) < -1 || S_ISDIR(buf.st_mode)){
        SendMessage("550 can't retreive file/dir.\r\n", server.conn_fd);
        fclose(fp);
        return -1;
    }
    if(server.mode == NOMODE) {
        SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
        fclose(fp);
        return -1;
    }
    SendMessage("150 ready for data connection.\r\n", server.conn_fd);
    if(server.mode == PASVMODE) {
        close(server.data_fd);
        server.data_fd = AccpetOutsider(server.listen_data_fd);
        if(server.data_fd < 0){
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            close(server.listen_data_fd);
            server.listen_data_fd = -1;
            fclose(fp);
            return -1;
        }
    }
    else if(server.mode == PORTMODE){
        close(server.data_fd);
        server.data_fd = ConnectOutsider(server.conn_ip, server.data_port);
        if(server.data_fd < 0){
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            fclose(fp);
            return -1;
        }
    }
    char file_buffer[MAXBUF];
    int len_buffer = MAXBUF;
    bzero(file_buffer, len_buffer);
    int file_buffer_len = 0;
    int byte_count = 0;
    server.data_flag = 1;
    while((file_buffer_len = fread(file_buffer, sizeof(char), MAXBUF, fp))>0){
        //printf("%d\n", file_buffer_len);
        if(send(server.data_fd, file_buffer, file_buffer_len, 0)<0){
            SendMessage("426 send file broken\r\n", server.conn_fd);
            printf("Error send\n");
            fclose(fp);
            if(server.mode == PASVMODE)close(server.listen_data_fd);
            close(server.data_fd);
            server.listen_data_fd = -1;
            server.data_fd = -1;
            server.data_flag = 0;
            server.mode = NOMODE;
            return -1;
        }
        byte_count += file_buffer_len;
        bzero(file_buffer, MAXBUF);
    }
    fclose(fp);
    if(server.mode == PASVMODE)close(server.listen_data_fd);
    SendMessage("226 retreive ok.\r\n", server.conn_fd);
    close(server.data_fd);
    server.listen_data_fd = -1;
    server.data_fd = -1;
    server.data_flag = 0;
    server.time_num++;
    server.time_byte += byte_count;
    server.total_byte += byte_count;
    server.mode = NOMODE;
    return 0;
}
int InputRMD(){
    char sentence[MAXBUF];
    if(CheckFilepath(server.info)<0 ||rmdir(server.info)<0){
        sprintf(sentence, "550 remove %s error\r\n", server.info);
        SendMessage(sentence, server.conn_fd);
        return -1;
    }
    else{
        SendMessage("250 remove ok\r\n", server.conn_fd);
        return 0;
    }
}
int InputRNFR(){
    //sprintf(sentence, "%s/%s", server.now_filepath, server.info);
    if(CheckFilepath(server.info)<0 || access(server.info, F_OK) != 0){
        SendMessage("550 renamefirst fail\r\n", server.conn_fd);
        return -1;
    }
    else{
        strcpy(server.old_name, server.info);
        server.rename_flag = 2;
        SendMessage("350 renamefirst ok\r\n", server.conn_fd);
        return 0;
    }
}
int InputRNTO(){
    if(server.rename_flag <= 0 ){
        SendMessage("503 not select file\r\n", server.conn_fd);
        return -1;
    }
    else{
        //sprintf(sentence, "%s/%s", server.now_filepath, server.info);
        if(CheckFilepath(server.info)<0 || rename(server.old_name, server.info) < 0){
            SendMessage("550 renamedo fail\r\n", server.conn_fd);
            return -1;
        }
        else{
            server.rename_flag = 0;
            SendMessage("250 renamedo ok\r\n", server.conn_fd);
            return 0;
        }
    }
}
int InputSTOR(){
    FILE *fp = fopen(server.info, "w");
    if(fp == NULL){
        SendMessage("452 can not write in.\r\n", server.conn_fd);
        return -1;
    }
    if(server.mode == NOMODE) {
        SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
        return -1;
    }
    SendMessage("150 ready for data connection.\r\n", server.conn_fd);
    if(server.mode == PASVMODE) {
        close(server.data_fd);
        server.data_fd = AccpetOutsider(server.listen_data_fd);
        if(server.data_fd < 0){
            close(server.listen_data_fd);
            server.listen_data_fd = -1;
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            return -1;
        }
    }
    else if(server.mode == PORTMODE){
        close(server.data_fd);
        server.data_fd = ConnectOutsider(server.conn_ip, server.data_port);
        if(server.data_fd < 0){
            SendMessage("425 no TCP connection was established.\r\n", server.conn_fd);
            return -1;
        }
    }
    char file_buffer[MAXBUF];
    int len_buffer = MAXBUF;
    int byte_count = 0;
    bzero(file_buffer, len_buffer);
    int file_buffer_len = 0;
    while(1){
        file_buffer_len = recv(server.data_fd, file_buffer, MAXBUF, 0);
        if(file_buffer_len == 0)break;
        if(file_buffer_len<0){
            SendMessage("426 receive file broken\r\n", server.conn_fd);
            printf("Error recv\n");
            fclose(fp);
            remove(server.info);
            if(server.mode == PASVMODE)close(server.listen_data_fd);
            close(server.data_fd);
            server.listen_data_fd = -1;
            server.data_fd = -1;
            server.data_flag = 0;
            server.mode = NOMODE;
            return -1;
        }
        len_buffer = fwrite(file_buffer, sizeof(char), file_buffer_len, fp);
        if(len_buffer < file_buffer_len) {
            SendMessage("451 write file error.\r\n", server.conn_fd);
            printf("Error fwrite\n");
            fclose(fp);
            remove(server.info);
            if(server.mode == PASVMODE)close(server.listen_data_fd);
            close(server.data_fd);
            server.listen_data_fd = -1;
            server.data_fd = -1;
            server.data_flag = 0;
            server.mode = NOMODE;
            return -1;
        }
        byte_count += file_buffer_len;
        bzero(file_buffer, MAXBUF);
    }
    fclose(fp);
    SendMessage("226 storage ok.\r\n", server.conn_fd);
    if(server.mode == PASVMODE)close(server.listen_data_fd);
    close(server.data_fd);
    server.listen_data_fd = -1;
    server.data_fd = -1;
    server.data_flag = 0;
    server.mode = NOMODE;
    server.time_num++;
    server.time_byte += byte_count;
    server.total_byte += byte_count;
    return 0;
}
int InputSYST(){
    if(server.info[0] == '\0'){
        SendMessage("215 UNIX Type: L8\r\n", server.conn_fd);
        return 0;
    }
    else{
        SendMessage("500 SYST must no argument.\r\n", server.conn_fd);
        return -1;
    }
}
int InputTYPE(){
    if(!strcmp(server.info, "I")){
        server.type_flag = 1;
        SendMessage("200 Type set to I.\r\n", server.conn_fd);
        return 0;
    }
    else{
        SendMessage("530 unvalid type\r\n", server.conn_fd);
        return -1;
    }
}
int InputUSER(){
    if(!strcmp(server.username, server.info)){
        server.user_flag = 1;
        SendMessage("331 Guest login ok, send your complete e-mail address as password.\r\n", server.conn_fd);
        return 0;
    }
    else{
        SendMessage("530 the username is unacceptable\r\n", server.conn_fd);
        return -1;
    }
}
void *FtpStart(int fd){
    server.conn_fd = fd;
    char sentence[MAXBUF];
    int len;
    InitTime();
    printf("accept ok\n");
    SendMessage("220 ftp.ssast.org FTP server ready\r\n", server.conn_fd);
    len = ReceiveMessage(sentence, server.conn_fd);
    while (len > 0){
        Split(sentence, server.order, server.info, ' ');
        if(!strcmp(server.order, "USER")){
            if(!InputUSER())
                break;
        }
        else SendMessage("530 input USER\r\n", server.conn_fd);
        len = ReceiveMessage(sentence, server.conn_fd);
    }
    if(len == 0)return NULL;
    len = ReceiveMessage(sentence, server.conn_fd);
    while (len > 0){
        Split(sentence, server.order, server.info, ' ');
        if(!strcmp(server.order, "PASS")){
            if(!InputPASS())
                break;
        }
        else SendMessage("530 please input PASS\r\n", server.conn_fd);
        len = ReceiveMessage(sentence, server.conn_fd);
    }
    if(len == 0)return NULL;
    while (1){
        if(server.rename_flag > 0)server.rename_flag--;
        len = ReceiveMessage(sentence, server.conn_fd);
        if(len <= 0) break;
        printf("%s",sentence);
        if(server.data_flag)continue;
        Split(sentence, server.order, server.info, ' ');
        switch (SwitchOrder(server.order)){
            case ABOR:
                InputABOR();
                break;
            case CWD:
                InputCWD();
                break;
            case DELE:
                InputDELE();
                break;
            case LIST:
                InputLIST();
                break;
            case MKD:
                InputMKD();
                break;
            case PASS:
                InputPASS();
                break;
            case PASV:
                InputPASV();
                break;
            case PORT:
                InputPORT();
                break;
            case PWD:
                InputPWD();
                break;
            case QUIT:
                InputQUIT();
                break;
            case RETR:
                InputRETR();
                break;
            case RMD:
                InputRMD();
                break;
            case RNFR:
                InputRNFR();
                break;
            case RNTO:
                InputRNTO();
                break;
            case STOR:
                InputSTOR();
                break;
            case SYST:
                InputSYST();
                break;
            case TYPE:
                InputTYPE();
                break;
            case USER:
                InputUSER();
                break;
            default:
                SendMessage("500 nonsupport order\r\n", server.conn_fd);
                break;
        }
        if(!strcmp(server.order, "QUIT") || !strcmp(server.order, "ABOR"))break;
    }
    close(server.data_fd);
    close(server.listen_data_fd);
    close(server.conn_fd);
    printf("close\n");
    return NULL;
}
int main(int argc, char **argv){
    int root_flag = 0;
    SetPort(&server.conn_port, SERVER_PORT);
    for (int i = 1; i < argc; i++){
        if(!strcmp("-port", argv[i])){
            i++;
            int base = 0, len = strlen(argv[i]);
            for(int j = 0; j < len; j++){
                if(argv[i][j] > '9' || argv[i][j] < '0'){
                    base  = -1;
                    break;
                }
                base = base * 10  + argv[i][j] - '0';
            }
            if(base > 0)SetPort(&server.conn_port, base);
        }
        else if(!strcmp("-root", argv[i])){
            i++;
            if(chdir(argv[i]) == 0){
                getcwd(server.root_filepath, 200);
                getcwd(server.now_filepath, 200);
                root_flag = 1;
            }
        }
    }
    if(!root_flag){
        //chdir("/tmp");
        getcwd(server.root_filepath, 200);
        getcwd(server.now_filepath, 200);
    }
    server.listen_conn_fd = ListenPort(server.conn_port);
    if(server.listen_conn_fd < 0)return 1;
    InitTotal();
    while (1){
        //int *conn_fd = malloc(sizeof(int *));
        //*conn_fd = AccpetOutsider(server.listen_conn_fd);
        //if(*conn_fd < 0)break;
        ///pthread_t pid;
        //pthread_create(&pid, NULL, FtpStart, (void *)conn_fd);
        int conn_fd = AccpetOutsider(server.listen_conn_fd);
        pid_t pid = -1;
        if((pid = fork())<0){
            printf("error in fork!");
        }
        else if(pid == 0){
            close(server.listen_conn_fd);
            FtpStart(conn_fd);
            exit(0);
        }
        else{
            close(server.conn_fd);
        }
//        FtpStart(conn_fd);
    }
    printf("end\n");
    close(server.listen_conn_fd);
    return 0;
}