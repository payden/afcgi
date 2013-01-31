#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "afcgi.h"
#include "fastcgi.h"

#define MAX_REQUESTS 65536
#define STATE_RECEIVED_BEGIN 1
#define STATE_RECEIVED_PARAMS 2
#define STATE_RECEIVED_STDIN 3


struct fcgi_request_s {
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

typedef struct fcgi_request_s fcgi_request_t;

struct record_buf_s {
  unsigned int size;
  unsigned char *start;
  unsigned char *real_start;
  unsigned char *pos;
};

typedef struct record_buf_s record_buf_t;

fcgi_request_t *_requests[MAX_REQUESTS];

void make_fcgi_header(fcgi_header *hdr, unsigned short request_id, unsigned short type);


void dump_params(fcgi_request_t *req)
{
  enum {name_length, value_length, name, value} state;
  unsigned int nlen;
  unsigned int vlen;
  state = name_length;

  char *idx = req->params_buf;
  while(idx < req->params_pos) {
    
    switch(state) {
      case name_length:
        if((*idx & 0x80) == 0x80) {
          nlen = ((*idx & 0x7f) << 24) + (*(idx+1) << 16) + (*(idx+2) << 8) + (*(idx+3) & 0xff);
          idx += 4;
        } else {
          nlen = *idx & 0xff;
          idx++;
        }
        state = value_length;
        break;
      case value_length:
        if((*idx & 0x80) == 0x80) {
          vlen = ((*idx & 0x7f) << 24) + (*(idx+1) << 16) + (*(idx+2) << 8) + (*(idx+3) & 0xff);
          idx += 4;
        } else {
          vlen = *idx & 0xff;
          idx++;
        }
        state = name;
        break;
      case name:
        fprintf(stderr, "%.*s = ", nlen, idx);
        idx += nlen;
        state = value;
        break;
      case value:
        fprintf(stderr, "%.*s\n", vlen, idx);
        idx += vlen;
        state = name_length;
        break;
      default:
        break;
    }

    
  }
  fprintf(stderr, "\n");
}


void send_response(fcgi_request_t *req, int sockfd)
{
  char outbuf[1024];
  fcgi_header *hdr = (fcgi_header *)&outbuf[0];
  char *body = &outbuf[sizeof(fcgi_header)];
  make_fcgi_header(hdr, req->id, FCGI_STDOUT);
  snprintf(body, 1016, "Content-Type: text/html\n\n<html>\n<head>\n<title>Test</title>\n</head>\n<body>\n<div>Test.</div>\n</body>\n</html>\n");
  hdr->contentLengthB0 = strlen(body);
  send(sockfd, outbuf, sizeof(fcgi_header) + strlen(body), 0);
  hdr->contentLengthB0 = 0;
  send(sockfd, outbuf, sizeof(fcgi_header), 0);
  memset(body, 0, sizeof(fcgi_end_request));
  hdr->type = FCGI_END_REQUEST;
  send(sockfd, outbuf, sizeof(fcgi_header) + sizeof(fcgi_end_request), 0);
  close(sockfd);
}

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
  unsigned short rec_len;
  ssize_t offset;
  fcgi_begin_request *begin_req;
  fcgi_request_t *cur_req = NULL;
  fcgi_header *resp_hdr;
  fcgi_header *hdr = (fcgi_header *)rec->start;
  req_id = (hdr->requestIdB1 << 8) + hdr->requestIdB0;
  rec_len = (hdr->contentLengthB1 << 8) + hdr->contentLengthB0;
  cur_req = _requests[req_id];
  if(!cur_req) {
    cur_req = (fcgi_request_t *)malloc(sizeof(fcgi_request_t));
    memset(cur_req, 0, sizeof(fcgi_request_t));
    cur_req->id = req_id;
    _requests[req_id] = cur_req;
  }
  switch(hdr->type) {
    case FCGI_BEGIN_REQUEST:
      begin_req = (fcgi_begin_request *)(rec->start + sizeof(fcgi_header));
      fprintf(stderr, "Received begin request.\n");
      fprintf(stderr, "Role: %hu\n", (begin_req->roleB1 << 8) + begin_req->roleB0);
      fprintf(stderr, "Flags: %u\n", begin_req->flags);
      fprintf(stderr, "Changing state to STATE_RECEIVED_BEGIN\n");
      cur_req->state = STATE_RECEIVED_BEGIN;
      break;
    case FCGI_PARAMS:
      if(!cur_req->params_pos) {
        cur_req->params_sz = 1024;
        cur_req->params_pos = cur_req->params_buf = (char *)malloc(cur_req->params_sz);
        memset(cur_req->params_pos, 0, cur_req->params_sz);
      }
      if(rec_len == 0) {
        //hit empty FCGI_PARAMS record so we're finished filling params_buf
        fprintf(stderr, "Changing state to STATE_RECEIVED_PARAMS\n");
        cur_req->state = STATE_RECEIVED_PARAMS;
        fprintf(stderr, "Dumping params for shits and giggles.\n");
        dump_params(cur_req);
        break;
      }

      //realloc if incoming FCGI_PARAMS are larger than params_buf, remember to track params_pos - params_buf offset because realloc may move memory location
      if(cur_req->params_sz - (cur_req->params_pos - cur_req->params_buf) <= rec_len) {
        cur_req->params_sz *= 2;
        offset = cur_req->params_pos - cur_req->params_buf;
        cur_req->params_buf = (char *)realloc(cur_req->params_buf, cur_req->params_sz);
        cur_req->params_pos = cur_req->params_buf + offset;
      }
      memcpy(cur_req->params_pos, rec->start + sizeof(fcgi_header), rec_len);
      cur_req->params_pos += rec_len;

      break;
    case FCGI_STDIN:
      if(!cur_req->stdin_pos) {
        cur_req->stdin_sz = 1024;
        cur_req->stdin_pos = cur_req->stdin_buf = (char *)malloc(cur_req->stdin_sz);
        memset(cur_req->stdin_pos, 0, cur_req->stdin_sz);
      }
      if(rec_len == 0) {
        //either empty FCGI_STDIN or we've received it already.
        fprintf(stderr, "Changing state to STATE_RECEIVED_STDIN\n");
        cur_req->state = STATE_RECEIVED_STDIN;
        fprintf(stderr, "Dumping stdin: %s\n", cur_req->stdin_buf);
        fprintf(stderr, "Let's send a response and close this request out.\n");
        send_response(cur_req, sockfd);
        if(cur_req->stdin_buf) {
          free(cur_req->stdin_buf);
        }
        if(cur_req->params_buf) {
          free(cur_req->params_buf);
        }
        _requests[req_id] = NULL;
        free(cur_req);
        cur_req = NULL;
        break;
      }

      if(cur_req->stdin_sz - (cur_req->stdin_pos - cur_req->stdin_buf) <= rec_len) {
        cur_req->stdin_sz *= 2;
        offset = cur_req->stdin_pos - cur_req->stdin_buf;
        cur_req->stdin_buf = (char *)realloc(cur_req->stdin_buf, cur_req->stdin_sz);
        cur_req->stdin_pos = cur_req->stdin_buf + offset;
      }
      memcpy(cur_req->stdin_pos, rec->start + sizeof(fcgi_header), rec_len);
      cur_req->stdin_pos += rec_len;

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
  ssize_t offset, real_offset;


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
      offset = record_buf->pos - record_buf->start;
      real_offset = record_buf->start - record_buf->real_start;
      fprintf(stderr, "DEBUG: expanding record buffer.\n");
      record_buf->real_start = (char *)realloc(record_buf->real_start, record_buf->size * 2);
      record_buf->start = record_buf->real_start + real_offset;
      record_buf->pos = record_buf->start + offset;
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

