#include <stdio.h>		// printf, fprintf
#include <stdlib.h>		// exit, atoi
#include <string.h>		// bzero, but you can use memset() instead
#include <unistd.h>		// standard symbolic constants and types
#include <sys/types.h> 	// system-related data types
#include <sys/socket.h>
#include <netinet/in.h>	// htons
#include <arpa/inet.h>

void dostuff(int sock);					// function prototype
void error(const char *msg){			// an inline function definition, no prototype needed 
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[]){
	int sockfd, newsockfd, portno, pid;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;

	if (argc < 2) 
		error("ERROR, no port provided");

	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// create a TCP socket 
	if (sockfd < 0) 				// if socket cannot be created
		error("ERROR opening socket");
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = atoi(argv[1]);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if( bind(sockfd, (struct sockaddr *) &serv_addr,	sizeof(serv_addr)) < 0) 
		error("ERROR on binding");

	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	while(1){					// server usually runs into a forever loop
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0) error("ERROR on accept");
		pid = fork();
		if(pid < 0) error("ERROR on accept");
		if(pid == 0){			// child process
			close(sockfd);		// close listening socket
			dostuff(newsockfd);	// communicate with the client
			exit(0);
		}
		else close(newsockfd);	// parent process, do nothing just continue listening
	}
	close(sockfd);				// close the listening socket, should never occur
	return 0; 
}

void dostuff (int sock){
	int n, i=0;
	char buffer[256];
	socklen_t sock_len;
	struct sockaddr_storage addr;
	char ipv4_addr[INET_ADDRSTRLEN];
	int port;

	sock_len = sizeof addr;
	getpeername(sock, (struct sockaddr*)&addr, &sock_len);
	if(addr.ss_family == AF_INET){
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ipv4_addr, sizeof ipv4_addr);
	}

	write(sock, "Halo from server!\n", 19);

	while(i<3){
		bzero(buffer,256);
		n = read(sock,buffer,255);
		if (n < 0) error("ERROR reading from socket");
		printf("Message from %s:%d: %s\n",ipv4_addr, port, buffer);
		// printf("Message from client: %s\n", buffer);
		n = write(sock,"I got your message",18);
		if (n < 0) error("ERROR writing to socket");
		i++;
	}
	close(sock);
}
	
