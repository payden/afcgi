#include "php.h"
#include "php_globals.h"
#include "php_variables.h"
#include "zend_modules.h"
#include "php.h"
#include "zend_ini_scanner.h"
#include "zend_globals.h"
#include "zend_stream.h"

#include "SAPI.h"

#include <stdio.h>

#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "zend.h"
#include "zend_extensions.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"
#include "fopen_wrappers.h"
#include "ext/standard/php_standard.h"

#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_highlight.h"
#include "zend_indent.h"
#include "php_getopt.h"
#include <php_config.h>


#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "afcgi.h"



char *afcgi_getenv(fcgi_request_t *req, const char *search_name);

int afcgi_finish_request(fcgi_request_t *req)
{
  char buf[16];
  char *body = &buf[sizeof(fcgi_header)];
  fcgi_header *hdr = (fcgi_header *)&buf[0];
  make_fcgi_header(hdr, req->id, FCGI_STDOUT);
  send(req->sockfd, buf, sizeof(fcgi_header), 0);

  hdr->contentLengthB0 = sizeof(fcgi_end_request);
  hdr->type = FCGI_END_REQUEST;
  memset(body, 0, sizeof(fcgi_end_request));
  send(req->sockfd, buf, sizeof(fcgi_header) + sizeof(fcgi_end_request), 0);
  close(req->sockfd);
  return 0;
}



int afcgi_send_stdout(fcgi_request_t *req, const char *str, uint str_length)
{
  char buf[1024 * 8];
  int n;
  uint max = (1024 * 8) - sizeof(fcgi_header);
  uint to_send = MIN(max, str_length);
  char *body = &buf[sizeof(fcgi_header)];
  fcgi_header *hdr = (fcgi_header *)&buf[0];
  make_fcgi_header(hdr, req->id, FCGI_STDOUT);
  hdr->contentLengthB1 = (to_send >> 8) & 0xff;
  hdr->contentLengthB0 = to_send & 0xff;
  memcpy(body, str, to_send);
  *(body+to_send) = '\0';
  n = send(req->sockfd, buf, sizeof(fcgi_header) + to_send, 0);
  return n - sizeof(fcgi_header);
}



static inline size_t sapi_afcgi_single_write(const char *str, uint str_length TSRMLS_DC)
{
  fprintf(stdout, "single_write: %s\n", str);
  return (size_t) str_length;
}

static int sapi_afcgi_ub_write(const char *str, uint str_length TSRMLS_DC)
{
  uint bytes_sent = 0;
  uint tmp_sent;
  fcgi_request_t *req = (fcgi_request_t *)SG(server_context);

  while(bytes_sent < str_length) {
    tmp_sent = afcgi_send_stdout(req, str + bytes_sent, str_length - bytes_sent);
    if(tmp_sent <= 0) {
      break;
    }
    bytes_sent += tmp_sent;
  }
  return (size_t) bytes_sent;
}

static void sapi_afcgi_flush(void *server_context)
{
  if (fflush(stdout) == EOF) {
    php_handle_aborted_connection();
  }
}

static void sapi_afcgi_log_message(char *message)
{
  fprintf(stderr, "log_message: %s\n", message);
}

static int sapi_afcgi_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
  sapi_header_struct *h;
  zend_llist_position pos;
  
  if(SG(request_info).no_headers == 1) {
    return SAPI_HEADER_SENT_SUCCESSFULLY;
  }

  h = (sapi_header_struct *)zend_llist_get_first_ex(&sapi_headers->headers, &pos);
  while (h) {
    if(h->header_len) {
      PHPWRITE_H(h->header, h->header_len);
      PHPWRITE_H("\r\n", 2);
    }
    h = (sapi_header_struct *)zend_llist_get_next_ex(&sapi_headers->headers, &pos);
  }
  PHPWRITE_H("\r\n", 2);

  return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static char *sapi_afcgi_getenv(char *name, size_t name_len TSRMLS_DC)
{
  return "";
}

static char *sapi_afcgi_putenv(char *name, char *value TSRMLS_DC)
{
  return NULL;
}

static int sapi_afcgi_read_post(char *buffer, uint count_bytes TSRMLS_DC)
{
  uint total_read = 0;
  fcgi_request_t *req = (fcgi_request_t *)SG(server_context);
  count_bytes = MIN(SG(request_info).content_length - SG(read_post_bytes), count_bytes);
  if(count_bytes > 0) {
    memcpy(buffer, req->stdin_buf, count_bytes);
  }

  return count_bytes;
  
}

static char *sapi_afcgi_read_cookies(TRSMLS_D)
{
  fcgi_request_t *req = (fcgi_request_t *)SG(server_context);
  if(req) {
    return afcgi_getenv(req, "HTTP_COOKIE");
  }
  return "";
}

static void sapi_afcgi_register_variables(zval *track_vars_array TSRMLS_DC)
{
  fcgi_request_t *req = (fcgi_request_t *)SG(server_context);
  char *request_uri = afcgi_getenv(req, "REQUEST_URI");
  char *request_method = afcgi_getenv(req, "REQUEST_METHOD");
  char *remote_addr = afcgi_getenv(req, "REMOTE_ADDR");
  if(request_uri) {
    php_register_variable("REQUEST_URI", request_uri, track_vars_array TSRMLS_CC);
    free(request_uri);
  }
  if(request_method) {
    php_register_variable("REQUEST_METHOD", request_method, track_vars_array TSRMLS_CC);
    free(request_method);
  }
  if(remote_addr) {
    php_register_variable("REMOTE_ADDR", remote_addr, track_vars_array TSRMLS_CC);
    free(remote_addr);
  }

}

static int sapi_afcgi_activate(TSRMLS_D)
{
  fprintf(stderr, "afcgi_activate called.\n");
  return SUCCESS;
}

static int sapi_afcgi_deactivate(TSRMLS_D)
{
  if(SG(sapi_started) && SG(server_context)) {
    fcgi_request_t *req = (fcgi_request_t *)SG(server_context);
    afcgi_finish_request(req);
  }
  if(SG(request_info).content_type) {
    free((void *)SG(request_info).content_type);
  }
  if(SG(request_info).request_uri) {
    free(SG(request_info).request_uri);
  }
  if(SG(request_info).query_string) {
    free(SG(request_info).query_string);
  }
  if(SG(request_info).request_method) {
    free(SG(request_info).request_method);
  }
  fprintf(stderr, "afcgi_deactivate called.\n");
  return SUCCESS;
}

static int sapi_afcgi_startup(sapi_module_struct *sapi_module)
{
  if (php_module_startup(sapi_module, NULL, 0) == FAILURE) {
    return FAILURE;
  }
  return SUCCESS;
}

static sapi_module_struct afcgi_sapi_module = {
  "afcgi",    /* name */
  "Asynchronous FastCGI",   /* pretty name */

  sapi_afcgi_startup,    /* startup */
  php_module_shutdown_wrapper,   /* shutdown */

  sapi_afcgi_activate,    /* activate */
  sapi_afcgi_deactivate,    /* deactivate */

  sapi_afcgi_ub_write,    /* unbuffered write */
  sapi_afcgi_flush,   /* flush */
  NULL,   /* get uid */
  sapi_afcgi_getenv,    /* get env */

  php_error,    /* error handler */

  NULL,   /* header handler */
  sapi_afcgi_send_headers,    /* send headers handler */
  NULL,   /* send header handler */
  
  sapi_afcgi_read_post,   /* read POST data */
  sapi_afcgi_read_cookies,    /* read cookies */

  sapi_afcgi_register_variables,    /* register server variables */
  sapi_afcgi_log_message,   /* log message */
  NULL,   /* get request time */
  NULL,   /* child terminate */

  STANDARD_SAPI_MODULE_PROPERTIES
};


static void init_request_info(TSRMLS_D)
{
  fcgi_request_t *req = (fcgi_request_t *)SG(server_context);
  SG(request_info).path_translated = NULL;
  SG(request_info).request_method = NULL;
  SG(request_info).proto_num = 1000;
  SG(request_info).query_string = NULL;
  SG(request_info).request_uri = NULL;
  SG(request_info).content_type = NULL;
  SG(request_info).content_length = 0;
  SG(sapi_headers).http_response_code = 200;

  char *content_length = afcgi_getenv(req, "CONTENT_LENGTH");
  char *content_type = afcgi_getenv(req, "CONTENT_TYPE");
  char *script_name = afcgi_getenv(req, "SCRIPT_FILENAME");
  char *request_uri = afcgi_getenv(req, "REQUEST_URI");
  char *query_string = afcgi_getenv(req, "QUERY_STRING");
  char *request_method = afcgi_getenv(req, "REQUEST_METHOD");
  if(content_length) {
    SG(request_info).content_length = atoi(content_length);
  }
  if(content_type) {
    SG(request_info).content_type = content_type;
  }
  if(script_name) {
    SG(request_info).path_translated = estrdup(script_name);
    free(script_name);
  }
  if(request_uri) {
    SG(request_info).request_uri = request_uri;
  }
  if(query_string) {
    SG(request_info).query_string = query_string;
  }
  if(request_method) {
    SG(request_info).request_method = request_method;
  }
}

char *afcgi_getenv(fcgi_request_t *req, const char *search_name)
{
  enum {name_length, value_length, name, value} state;
  unsigned int nlen;
  unsigned int vlen;
  unsigned int search_len = strlen(search_name);
  char *ret = NULL;
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
        if(nlen == search_len && strncmp(search_name, idx, nlen) == 0) {
          idx += nlen;
          ret = (char *)malloc(vlen + 1);
          memcpy(ret, idx, vlen);
          *(ret+vlen) = '\0';
          return ret;
        }
        idx += nlen;
        state = value;
        break;
      case value:
        idx += vlen;
        state = name_length;
        break;
      default:
        break;
    }
  }
  return ret;
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
  zend_file_handle file_handle;
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
    cur_req->sockfd = sockfd;
    _requests[req_id] = cur_req;
  }
  switch(hdr->type) {
    case FCGI_BEGIN_REQUEST:
      begin_req = (fcgi_begin_request *)(rec->start + sizeof(fcgi_header));
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
        SG(server_context) = (void *)cur_req;
        init_request_info(TSRMLS_C);
        if (php_request_startup(TSRMLS_C) == FAILURE) {
          fprintf(stderr, "php_request_startup failure.\n");
          exit(0);
        }
        if (php_fopen_primary_script(&file_handle TSRMLS_CC) == FAILURE) {
          fprintf(stderr, "open_primary_script failed.\n");
          exit(0);
        }
        fprintf(stderr, "Request method: %s\n", SG(request_info).request_method);
        fprintf(stderr, "Post data: %s\n", SG(request_info).post_data);
        php_execute_script(&file_handle TSRMLS_CC);
        STR_FREE(SG(request_info).path_translated);
        SG(request_info).path_translated = NULL;
        php_request_shutdown((void *)0);
        SG(server_context) = NULL;
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
      fprintf(stderr, "DEBUG: New FCGI record.\n");
      if(record_buf->pos - record_buf->start < 8) {
        fprintf(stderr, "DEBUG: Haven't received 8 bytes yet.\n");
        continue;
      }
      new_record = 0;
      hdr = (fcgi_header *)record_buf->start;
      current_request_id = (hdr->requestIdB1 << 8) + hdr->requestIdB0;
      current_record_content_length = (hdr->contentLengthB1 << 8) + hdr->contentLengthB0;
      current_record_padding_length = hdr->paddingLength;

      fprintf(stderr, "DEBUG: FCGI Record Info\n  current_request_id: %hu\n  content_length: %hu\n  padding_length: %u\n\n", current_request_id, current_record_content_length, current_record_padding_length);

    }

    if(record_buf->pos - record_buf->start < sizeof(fcgi_header) + current_record_content_length + current_record_padding_length) {
      fprintf(stderr, "DEBUG: Continuing not enough data yet.\n");
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
  fprintf(stderr, "DEBUG: Connection closed.\n\n");
  return 0;
}

int main(int argc, char **argv)
{
  zend_file_handle file_handle;
  signal(SIGPIPE, SIG_IGN);
#ifdef ZTS
  void ***tsrm_ls;
  tsrm_startup(1, 1, 0, NULL);
  tsrm_ls = ts_resource(0);
#endif

  sapi_startup(&afcgi_sapi_module);

  if (afcgi_sapi_module.startup(&afcgi_sapi_module) == FAILURE) {
    fprintf(stderr, "->startup fail\n");
    exit(0);
  }

  struct addrinfo hints, *p = NULL, *servinfo = NULL;
  struct sockaddr_in addr;
  socklen_t addrsize;
  int rv;
  int listen_fd;
  int yes = 1;
  int client_fd;

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

  int i;
  for(i=0;i<1;i++) {
    if(!fork()) {
      goto accept;
    }
  }
  goto out;

accept:

  addrsize = sizeof(struct sockaddr_in);
  client_fd = accept(listen_fd, (struct sockaddr *)&addr, &addrsize);
  if(client_fd == -1) {
    perror("accept");
    exit(-3);
  }

  recv_loop(client_fd);
  goto accept;

out:

  for(i=0;i<4;i++) {
    wait(NULL);
  }
  fprintf(stderr, "Done.\n");
  
  return 0;
}

