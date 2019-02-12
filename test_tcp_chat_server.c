#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 10241

int main(int argc, char const *argv[]){
    
    struct sockaddr_in address;
    int sock, new_socket;
    int opt = 1;
    int addrlen = sizeof(address);
    char rcvdBuf[BUFFER_SIZE];
    char sendBuf[BUFFER_SIZE];

    int read_cnt;
    FILE *fp;

    fp = fopen("Speech.mp3", "rb");
    
    // Creating socket
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
        perror("socket failed");
        return -1;
    }

    memset(&address, '0', sizeof(address));

    address.sin_family = PF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind
    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) == -1 ){
        perror("bind failed");
        return -1;
    }
    
    // Listen
    if(listen(sock, 3) == -1 ){
        perror("listen");
        return -1;
    }

    // Accept
    new_socket = accept(sock, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if(new_socket == -1) {
        perror("accept");
        return -1;
    }

    while(1){
        memset(rcvdBuf, 0, sizeof(rcvdBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
/*
        ssize_t rval = recv(new_socket, rcvdBuf, BUFFER_SIZE, 0);
        
        if(rval == -1)
            break;
        else
            printf("Client: %s\n", rcvdBuf);

        if(strcmp(rcvdBuf, "/quit\n") == 0)
            break;

        printf("Server: ");
        fgets(sendBuf, BUFFER_SIZE, stdin);
        printf("\n");

        if(send(new_socket, sendBuf, strlen(sendBuf), 0) == -1)
            break;  

        if(strcmp(sendBuf, "/quit\n") == 0)
            break;
*/
    read_cnt = fread((void*)sendBuf, 1, BUFFER_SIZE, fp);
    if(read_cnt < BUFFER_SIZE) {
        write(new_socket, BUFFER_SIZE, read_cnt);
        break;
    }
    write(new_socket, sendBuf, BUFFER_SIZE);

    }

    fclose(fp);
    close(sock);
    close(new_socket);

    return 0;
}