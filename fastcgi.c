#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "afcgi.h"
#include "fastcgi.h"

#define MAX_REQUESTS 65536
#define STATE_RECEIVED_BEGIN 1


struct fcgi_request_s {
  unsigned short id;
  unsigned short params_len;
  unsigned short stdin_len;
  char *params_buf;
  char *stdin_buf;
  unsigned char state;
  unsigned char reserved;
};

typedef struct fcgi_request_s fcgi_request_t;

struct record_buf_s {
  unsigned int size;
  unsigned char *start;
  unsigned char *real_start;
  unsigned char *pos;
};

typedef struct record_buf_s record_buf_t;

fcgi_request_t *_requests[MAX_REQUESTS];


void make_fcgi_header(fcgi_header *hdr, unsigned short request_id, unsigned short type)
{
  memset(hdr, 0, sizeof(fcgi_header));
  hdr->version = FCGI_VERSION_1;
  hdr->type = type;
  hdr->requestIdB1 = request_id >> 8;
  hdr->requestIdB0 = request_id & 0xff;
}

int process_record(record_buf_t *rec, int sockfd)
{
  int x;
  char out_buf_temp[1024];
  char timestr[200];
  unsigned short req_id;
  fcgi_begin_request *begin_req;
  fcgi_request_t *cur_req = NULL;
  fcgi_header *resp_hdr;
  fcgi_header *hdr = (fcgi_header *)rec->start;
  req_id = (hdr->requestIdB1 << 8) + hdr->requestIdB0;
  cur_req = _requests[req_id];
  if(!cur_req) {
    cur_req = (fcgi_request_t *)malloc(sizeof(fcgi_request_t));
    memset(cur_req, 0, sizeof(fcgi_request_t));
    cur_req->id = req_id;
  }
  switch(hdr->type) {
    case FCGI_BEGIN_REQUEST:
      begin_req = (fcgi_begin_request *)(rec->start + sizeof(fcgi_header));
      fprintf(stderr, "Received begin request.\n");
      fprintf(stderr, "Role: %hu\n", (begin_req->roleB1 << 8) + begin_req->roleB0);
      fprintf(stderr, "Flags: %u\n", begin_req->flags);
      req->state = STATE_RECEIVED_BEGIN;
      break;
    case FCGI_PARAMS:
      //handle fcgi_params
      break;
    case FCGI_STDIN:
      //handle fcgi_stdin
      break;
    default:
      break;
  }



  /*
  if(hdr->type == FCGI_STDIN) {
    fprintf(stderr, "Sending back a response!\n");
    make_fcgi_header((fcgi_header *)&out_buf_temp, (hdr->requestIdB1 << 8) + hdr->requestIdB0, FCGI_STDOUT);
    snprintf(timestr, 200, "Content-Type: text/html\n\n<html><body><h1>The Current epoch is: %d</h1></body></html>\n", time(NULL));
    strncpy(&out_buf_temp[8], timestr, 200);
    ((fcgi_header *)&out_buf_temp)->contentLengthB0 = strlen(timestr);
    send(sockfd, out_buf_temp, sizeof(fcgi_header) + strlen(timestr), 0);
    ((fcgi_header *)&out_buf_temp)->contentLengthB0 = 0;
    send(sockfd, out_buf_temp, sizeof(fcgi_header), 0);
    ((fcgi_header *)&out_buf_temp)->type = FCGI_END_REQUEST;
    memset(&out_buf_temp[8], 0, 8);
    send(sockfd, out_buf_temp, sizeof(fcgi_header) + 8, 0);
    close(sockfd);
    if(cur_req) {
      if(cur_req->stdin_buf) {
        free(cur_req->stdin_buf);
      }
      if(cur_req->params_buf) {
        free(cur_req->params_buf);
      }
    }
    return 0;
  }
  */
  return 1;

}

int recv_loop(int sockfd)
{
  fcgi_request_t *cur_req;
  record_buf_t *record_buf;
  char recv_buf[1024];
  fcgi_header *hdr;


  unsigned short current_request_id = 0;
  unsigned short current_record_content_length = 0;
  unsigned char current_record_padding_length = 0;
  unsigned char new_record = 1;

  record_buf = (record_buf_t *)malloc(sizeof(record_buf_t));
  memset(record_buf, 0, sizeof(record_buf_t));
  record_buf->pos = record_buf->start = record_buf->real_start = (char *)malloc(1024);
  record_buf->size = 1024;
  memset(record_buf->start, 0, 1024);

  memset(_requests, 0, sizeof(fcgi_request_t *) * MAX_REQUESTS);

  int n = 0;
  while(n >= 0) {
    n = recv(sockfd, recv_buf, 1024, 0);
    if(n == -1 || n == 0) {
      break;
    }
    fprintf(stderr, "DEBUG: received (%d)\n", n);

    if((record_buf->pos - record_buf->start) + n > record_buf->size) {
      fprintf(stderr, "DEBUG: expanding record buffer.\n");
      record_buf->start = (char *)realloc(record_buf->start, record_buf->size * 2);
      record_buf->size *= 2;
    }
    memcpy(record_buf->pos, recv_buf, n);
    record_buf->pos += n;


    if(new_record) {
newrec:
      fprintf(stderr, "New record.\n");
      if(record_buf->pos - record_buf->start < 8) {
        fprintf(stderr, "Haven't received 8 bytes yet.\n");
        continue;
      }
      fprintf(stderr, "Set new record to zero.\n");
      new_record = 0;
      hdr = (fcgi_header *)record_buf->start;
      current_request_id = (hdr->requestIdB1 << 8) + hdr->requestIdB0;
      current_record_content_length = (hdr->contentLengthB1 << 8) + hdr->contentLengthB0;
      current_record_padding_length = hdr->paddingLength;

      fprintf(stderr, "In recv_loop current_request_id, content_length, padding_length: %hu, %hu, %u\n", current_request_id, current_record_content_length, current_record_padding_length);

    }

    if(record_buf->pos - record_buf->start < sizeof(fcgi_header) + current_record_content_length + current_record_padding_length) {
      fprintf(stderr, "Continuing not enough data yet.\n");
      continue;
    }
    if(!process_record(record_buf, sockfd)) {
      if(record_buf->real_start) {
        free(record_buf->real_start);
      }
      return 0;
    }
    record_buf->start += sizeof(fcgi_header) + current_record_content_length + current_record_padding_length;
    if(record_buf->pos - record_buf->start > 0) {
      goto newrec;
    }

    //processed all records and data
    new_record = 1;
    record_buf->pos = record_buf->start = record_buf->real_start;
  }
  fprintf(stderr, "Connection was closed.\nChild exiting.\n");
  return 0;
}

