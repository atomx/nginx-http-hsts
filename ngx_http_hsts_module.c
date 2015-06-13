
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
  ngx_flag_t preload;
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
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
  ngx_uint_t i;
  ngx_http_hsts_loc_conf_t* conf = confp;
  ngx_str_t *values = cf->args->elts;

  if (values[1].len > 0) {
    if (ngx_strncmp("off", values[1].data, values[1].len) == 0) {
      conf->expires = 0;
    } else {
      struct tm tm;

      // Make sure the string is long enough for strptime in case it's not null terminated.
      if (values[1].len < strlen("2015-05-29")) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
        return NGX_CONF_ERROR;
      }

      ngx_memzero(&tm, sizeof(tm));

      if (strptime((char*)values[1].data, "%Y-%m-%d", &tm) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
        return NGX_CONF_ERROR;
      }

      conf->expires = timegm(&tm);

      if (conf->expires == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
        return NGX_CONF_ERROR;
      }
    }
  }

  for (i = 2; i < cf->args->nelts; i++) {
    if (ngx_strncmp("includeSubdomains", values[i].data, values[i].len) == 0) {
      conf->includeSubdomains = 1;
    } else if (ngx_strncmp("preload", values[i].data, values[i].len) == 0) {
      conf->preload = 1;
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
  conf->preload = NGX_CONF_UNSET_UINT;

  return conf;
}


static char *ngx_http_hsts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_hsts_loc_conf_t *prev = parent;
  ngx_http_hsts_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->expires, prev->expires, 0);
  ngx_conf_merge_value(conf->includeSubdomains, prev->includeSubdomains, 0);
  ngx_conf_merge_value(conf->preload, prev->preload, 0);

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

  // 64 is enough, see:
  // echo -n "max-age=2147483648; includeSubdomains; preload" | wc -c
  u_char *val = ngx_pnalloc(r->pool, 64);
  if (val == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  u_char *p = ngx_snprintf(
    val,
    64,
    "max-age=%l%s%s",
    conf->expires - time(NULL),
    conf->includeSubdomains ? "; includeSubdomains" : "",
    conf->preload ? "; preload" : ""
  );

  ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  h->hash = 1;
  ngx_str_set(&h->key, "Strict-Transport-Security");

  h->value.len = p - val;
  h->value.data = (u_char*)val;

  return ngx_http_next_header_filter(r);
}

