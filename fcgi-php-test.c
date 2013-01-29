#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <fastcgi.h>

void dump_data(unsigned char *buf, unsigned short len);
void add_param(unsigned char *buf, unsigned short *idx, const char *name, const char *value);

int main(int argc, char **argv) {
  struct addrinfo hints, *servinfo, *p;
  int rv, sockfd;
  FCGI_BeginRequestRecord *begin_record = NULL;
  FCGI_Header *header_ptr = NULL;
  char buf[1024];
  char body_buf[1024];
  unsigned short body_idx = 0;
  unsigned short request_id = 0;
  unsigned short content_length = 0;
  unsigned int n;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if((rv = getaddrinfo("localhost","9001", &hints, &servinfo)) != 0) {
    fprintf(stderr, "Error getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  for(p = servinfo; p != NULL; p = p->ai_next) {
    if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      continue;
    }
    if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo);
  if(p == NULL) {
    fprintf(stderr, "Unable to connect.\n");
    exit(1);
  }
  memset(buf, 0, 1024);
  request_id = 1;
  begin_record = (FCGI_BeginRequestRecord *)&buf;
  begin_record->header.version = FCGI_VERSION_1;
  begin_record->header.type = FCGI_BEGIN_REQUEST;
  begin_record->header.requestIdB1 = request_id >> 8 & 0xff;
  begin_record->header.requestIdB0 = request_id & 0xff;
  begin_record->header.contentLengthB1 = (8 >> 8) & 0xff;
  begin_record->header.contentLengthB0 = 8 & 0xff;
  begin_record->header.paddingLength = 0;
  begin_record->header.reserved = 0;
  begin_record->body.roleB1 = FCGI_RESPONDER >> 8 & 0xff; //always 0 right now
  begin_record->body.roleB0 = FCGI_RESPONDER & 0xff; //FCGI_RESPONDER
  n = send(sockfd, buf, sizeof(FCGI_BeginRequestRecord), 0);
  memset(buf, 0, 1024);
  header_ptr = (FCGI_Header *)&buf;
  header_ptr->version = FCGI_VERSION_1;
  header_ptr->type = FCGI_PARAMS;
  header_ptr->requestIdB1 = (request_id >> 8) & 0xff;
  header_ptr->requestIdB0 = request_id & 0xff;
  //manually pack some FCGI_PARAMS
  memset(body_buf, 0, 1024);
  body_idx = 0;
  add_param(body_buf, &body_idx, "SCRIPT_FILENAME", "/home/payden/work/cs/login.php");
  add_param(body_buf, &body_idx, "REQUEST_METHOD", "GET");
  add_param(body_buf, &body_idx, "SCRIPT_NAME", "/login.php");
  add_param(body_buf, &body_idx, "REQUEST_URI", "/login.php");
  add_param(body_buf, &body_idx, "DOCUMENT_URI", "/login.php");
  add_param(body_buf, &body_idx, "DOCUMENT_ROOT", "/home/payden/work/cs");
  add_param(body_buf, &body_idx, "SERVER_PROTOCOL", "HTTP/1.1");
  add_param(body_buf, &body_idx, "GATEWAY_INTERFACE", "CGI/1.1");
  add_param(body_buf, &body_idx, "SERVER_SOFWTARE", "PKS FCGI LIB");
  add_param(body_buf, &body_idx, "REMOTE_ADDR", "127.0.0.1");
  add_param(body_buf, &body_idx, "REMOTE_PORT", "58014");
  add_param(body_buf, &body_idx, "SERVER_ADDR", "127.0.0.1");
  add_param(body_buf, &body_idx, "SERVER_PORT", "9000");
  add_param(body_buf, &body_idx, "SERVER_NAME", "cs.localhost.net");
  add_param(body_buf, &body_idx, "QUERY_STRING", "");
  header_ptr->contentLengthB1 = (body_idx >> 8) & 0xff;
  header_ptr->contentLengthB0 = body_idx & 0xff;
  //send out header and body
  n = send(sockfd, buf, sizeof(FCGI_Header), 0);
  n = send(sockfd, body_buf, body_idx, 0);
  memset(buf, 0, 1024);
  //Empty FCGI_PARAMS
  header_ptr->version = FCGI_VERSION_1;
  header_ptr->type = FCGI_PARAMS;
  header_ptr->requestIdB1 = (request_id >> 8) & 0xff;
  header_ptr->requestIdB0 = request_id & 0xff;
  header_ptr->contentLengthB1 = 0;
  header_ptr->contentLengthB0 = 0;
  n = send(sockfd, buf, sizeof(FCGI_Header), 0);
  //Empty FCGI_STDIN
  header_ptr->type = FCGI_STDIN;
  n = send(sockfd, buf, sizeof(FCGI_Header), 0);
  memset(buf, 0, 1024);
  n = recv(sockfd, buf, 1024, 0);
  fprintf(stderr, "Received (%u)\n", n);
  dump_data(buf, n);
  close(sockfd);
  return 0;
}

void dump_data(unsigned char *buf, unsigned short len) {
  int i;
  for(i=0;i<len;i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
  fprintf(stderr, "\n");
}

void add_param(unsigned char *buf, unsigned short *idx, const char *name, const char *value) {
  unsigned short int namelen, valuelen;
  namelen = strlen(name);
  valuelen = strlen(value);
  buf[*idx] = namelen;
  *idx += 1;
  buf[*idx] = valuelen;
  *idx += 1;
  memcpy(buf + *idx, name, namelen);
  *idx += namelen;
  memcpy(buf + *idx, value, valuelen);
  *idx += valuelen;
}
