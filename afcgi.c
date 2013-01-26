#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>


#include "afcgi.h"

int main(int argc, char **argv)
{
  struct addrinfo hints, *p = NULL, *servinfo = NULL;
  struct sockaddr_in addr;
  socklen_t addrsize;
  int rv;
  int listen_fd;
  int yes = 1;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if((rv = getaddrinfo(NULL, "9001", &hints, &servinfo)) != 0) {
    fprintf(stderr, "Error getaddrinfo: %s\n", gai_strerror(rv));
    exit(-1);
  }

  for(p = servinfo; p != NULL; p = p->ai_next) {
    listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    
    if(listen_fd == -1) {
      perror("socket");
      continue;
    }
    
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    
    if(bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(listen_fd);
      continue;
    }

    break;
  }

  freeaddrinfo(servinfo);

  if(p == NULL) {
    fprintf(stderr, "Failed to bind.\n");
    exit(-2);
  }

  if(listen(listen_fd, LISTEN_BACKLOG) == -1) {
    fprintf(stderr, "listen failed.\n");
    exit(-3);
  }

  addrsize = sizeof(struct sockaddr_in);
  fprintf(stderr, "Accepted: %d\n", accept(listen_fd, (struct sockaddr *)&addr, &addrsize));
  perror("accept");
  fprintf(stderr, "Done.\n");
  
  return 0;
}