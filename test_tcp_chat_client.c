#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 10241

int main(int argc, char const *argv[]){

    int sock;
    struct sockaddr_in serv_addr;

    FILE *fp;
    int read_cnt;

    char sendBuf[BUFFER_SIZE];
    char rcvdBuf[BUFFER_SIZE];

    char file_name[BUFFER_SIZE];
    printf("%s\n", file_name);
    fp = fopen(file_name, "wb");

    // Createing socket
    if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ){
        printf("\n Socket creation error \n");
        return -1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = PF_INET;
    serv_addr.sin_port = htons(PORT);

    //Convert IPv4 and IPv6 address from text to binary form
    if(inet_pton(PF_INET, "127.0.0.1", &serv_addr.sin_addr) == -1 ){
        printf("\nInvalid address/ Address not supported \n ");
        return -1;
    }

    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1 ){
        printf("\nConnection Failed \n");
        return -1;
    }

    while(1) {
        memset(sendBuf, 0, sizeof(sendBuf));
        memset(rcvdBuf, 0, sizeof(rcvdBuf));
/*
        printf("Client: ");
        fgets(sendBuf, BUFFER_SIZE, stdin);
        printf("\n");

        if(send(sock, sendBuf, strlen(sendBuf), 0) == -1)
            break;

        if(strcmp(sendBuf, "/quit\n") == 0)
            break;

        if(recv(sock, rcvdBuf, BUFFER_SIZE, 0) == -1)
            break;

        if(strcmp(rcvdBuf, "/quit\n") == 0)
            break;
        else
            printf("Server: %s\n", rcvdBuf);
*/
        read_cnt = read(sock, rcvdBuf, BUFFER_SIZE);
        fwrite((void*)rcvdBuf, 1, read_cnt, fp);
    }

    fclose(fp);
    close(sock);

    return 0;
}