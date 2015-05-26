
// _GNU_SOURCE needs to be defined for strptime to be exported.
#ifndef _GNU_SOURCE
# define _NO_GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <time.h>
#ifdef _NO_GNU_SOURCE
# undef _NO_GNU_SOURCE
# undef _GNU_SOURCE
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_hsts_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_hsts_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hsts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_hsts_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_hsts_header_filter(ngx_http_request_t *r);


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


typedef struct {
  time_t     expires;
  ngx_flag_t includeSubdomains;
} ngx_http_hsts_loc_conf_t;


static ngx_http_module_t  ngx_http_hsts_module_ctx = {
  NULL,                           /* preconfiguration */
  ngx_http_hsts_init,             /* postconfiguration */

  NULL,                           /* create main configuration */
  NULL,                           /* init main configuration */

  NULL,                           /* create server configuration */
  NULL,                           /* merge server configuration */

  ngx_http_hsts_create_loc_conf,  /* create location configuration */
  ngx_http_hsts_merge_loc_conf    /* merge location configuration */
};


static ngx_command_t ngx_http_hsts_commands[] = {
    { ngx_string("hsts"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_hsts_config,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};


ngx_module_t  ngx_http_hsts_module = {
  NGX_MODULE_V1,
  &ngx_http_hsts_module_ctx,  /* module context */
  ngx_http_hsts_commands,     /* module directives */
  NGX_HTTP_MODULE,            /* module type */
  NULL,                       /* init master */
  NULL,                       /* init module */
  NULL,                       /* init process */
  NULL,                       /* init thread */
  NULL,                       /* exit thread */
  NULL,                       /* exit process */
  NULL,                       /* exit master */
  NGX_MODULE_V1_PADDING
};


static char *ngx_http_hsts_config(ngx_conf_t *cf, ngx_command_t *cmd, void *confp) {
  ngx_http_hsts_loc_conf_t* conf = confp;
  ngx_str_t *values = cf->args->elts;

  if (values[1].len > 0) {
    char* expires = malloc(values[1].len + 1);
    ngx_memcpy(expires, values[1].data, values[1].len);

    struct tm tm;
    if (strptime(expires, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
      free(expires);

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
      return NGX_CONF_ERROR;
    }

    free(expires);

    conf->expires = timegm(&tm);

    if (conf->expires == -1) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
      return NGX_CONF_ERROR;
    }
  }

  if (cf->args->nelts > 2) {
    if (ngx_strncmp("includeSubdomains", values[2].data, values[2].len) == 0) {
      conf->includeSubdomains = 1;
    } else {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown option %*s", values[2]);
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;
}


static void *ngx_http_hsts_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_hsts_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hsts_loc_conf_t));
  if (conf == NULL) {
      return NULL;
  }
    
  conf->expires = NGX_CONF_UNSET;
  conf->includeSubdomains = NGX_CONF_UNSET_UINT;

  return conf;
}


static char *ngx_http_hsts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_hsts_loc_conf_t *prev = parent;
  ngx_http_hsts_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->expires, prev->expires, 0);
  ngx_conf_merge_value(conf->includeSubdomains, prev->includeSubdomains, 0);

  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_hsts_init(ngx_conf_t *cf) {
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_hsts_header_filter;

  return NGX_OK;
}


static ngx_int_t ngx_http_hsts_header_filter(ngx_http_request_t *r) {
  if (r->connection->ssl == NULL) {
    return ngx_http_next_header_filter(r);
  }

  ngx_http_hsts_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_hsts_module);

  if (conf->expires == 0) {
    return ngx_http_next_header_filter(r);
  }

  ngx_table_elt_t* h = ngx_list_push(&r->headers_out.headers);

  if (h == NULL) {
    return ngx_http_next_header_filter(r);
  }

  // 40 is enought, see:
  // echo -n "max-age=2147483648; includeSubdomains" | wc -c
  char *val = ngx_palloc(r->pool, 40);
  if (val == NULL) {
    return ngx_http_next_header_filter(r);
  }

  size_t hvallen = snprintf(val, 40, "max-age=%ld%s", conf->expires - time(0), conf->includeSubdomains ? "; includeSubdomains" : "");

  ngx_table_elt_t *info_header = ngx_list_push(&r->headers_out.headers);
  if (info_header == NULL) {
    return ngx_http_next_header_filter(r);
  }

  info_header->hash = 1;
  ngx_str_set(&info_header->key, "Strict-Transport-Security");

  ngx_str_t hval;
  hval.len = hvallen;
  hval.data = (u_char*)val;

  info_header->value = hval;

  return ngx_http_next_header_filter(r);
}

