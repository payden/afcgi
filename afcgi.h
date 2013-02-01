#include "fastcgi.h"

#define LISTEN_BACKLOG 10
#define MAX_REQUESTS 65536
#define STATE_RECEIVED_BEGIN 1
#define STATE_RECEIVED_PARAMS 2
#define STATE_RECEIVED_STDIN 3

struct fcgi_request_s {
  int sockfd;
  unsigned short id;
  unsigned short params_sz;
  unsigned short stdin_sz;
  char *params_buf;
  char *params_pos;
  char *stdin_buf;
  char *stdin_pos;
  unsigned char state;
  unsigned char reserved;
};

struct record_buf_s {
  unsigned int size;
  unsigned char *start;
  unsigned char *real_start;
  unsigned char *pos;
};


typedef struct fcgi_request_s fcgi_request_t;
typedef struct record_buf_s record_buf_t;

fcgi_request_t *_requests[MAX_REQUESTS];

void make_fcgi_header(fcgi_header *hdr, unsigned short request_id, unsigned short type);
int recv_loop(int sockfd);
