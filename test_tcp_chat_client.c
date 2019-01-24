#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]){

    int sock;
    struct sockaddr_in serv_addr;

    char sendBuf[BUFFER_SIZE];
    char rcvdBuf[BUFFER_SIZE];

    // socket(domain, type, protocol), domain = AF_INET (IPv4), type = SOCK_STREAM (TCP), protocol = 0 (default)
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
        printf("\n Socket creation error \n");
        return -1;
    }

    // memset(void *dest, int c, size_t count) -> dest의 count 개의 바이트를 값 c로 설정함
    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    //Convert IPv4 and IPv6 address from text to binary form
    if(inet_pton(AF_INET, "192.168.1.61", &serv_addr.sin_addr) <= 0 ){
        printf("\nInvalid address/ Address not supported \n ");
        return -1;
    }

    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 ){
        printf("\nConnection Failed \n");
        return -1;
    }

    while(1) {
        memset(sendBuf, 0, sizeof(sendBuf));
        memset(rcvdBuf, 0, sizeof(rcvdBuf));

        printf("Client: ");
        fgets(sendBuf, BUFFER_SIZE, stdin);

        if(send(sock, sendBuf, strlen(sendBuf), 0) == -1)
            return -1;

        if(recv(sock, rcvdBuf, BUFFER_SIZE, 0) == -1)
            return -1;
        else
            printf("Server: %s\n", rcvdBuf);
    }

    fputc('\n', stdout);
    close(sock);

    return 0;
}