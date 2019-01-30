#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]){
    
    struct sockaddr_in address;
    int sock, new_socket;
    int opt = 1;
    int addrlen = sizeof(address);
    char Buf[BUFFER_SIZE];
    char message[BUFFER_SIZE];
    
    // Creating socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        perror("socket failed");
        return -1;
    }

    memset(&address, '0', sizeof(address));

    address.sin_family = AF_INET;
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
        memset(Buf, 0, sizeof(Buf));
        memeset(message, 0, sizeof(message));

        ssize_t rval = recv(new_socket, Buf, BUFFER_SIZE, 0);
        
        if(rval == -1)
            return -1;
        else
            printf("Client: %s\n", Buf);

        printf("Server: ");
        fgets(message, BUFFER_SIZE, stdin);

        if(send(new_socket, message, strlen(message), 0) == -1)
            return -1;  

        if(strcmp(message, "/quit\n") == 0)
            break;
    }

    close(sock);
    close(new_socket);

    return 0;
}