#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]){
    
    struct sockaddr_in address;
    int server_fd, new_socket;
    int opt = 1;
    int addrlen = sizeof(address);
    char sendBuf[BUFFER_SIZE];
    char rcvdBuf[BUFFER_SIZE];

    //Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    //Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if(listen(server_fd, 3) < 0 ){
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0 ){
        perror("accept");
        exit(EXIT_FAILURE);
    }

    while(1){
        memset(sendBuf, 0, sizeof(sendBuf));
        memset(rcvdBuf, 0, sizeof(rcvdBuf));

        if(recv(server_fd, rcvdBuf, BUFFER_SIZE, 0) == -1)
            return -1;
        else
            printf("Client: %s\n", rcvdBuf);

        printf("Server: ");
        fgets(sendBuf, BUFFER_SIZE, stdin);

        if(send(server_fd, sendBuf, strlen(sendBuf), 0) == -1)
            return -1;
        
    }

    return 0;
}