
#define _GNU_SOURCE
#include <time.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void *ngx_http_hsts_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hsts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_hsts_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_hsts_handler(ngx_http_request_t *r);


typedef struct {
  ngx_str_t expires;
  time_t    expires_time;
} ngx_http_hsts_loc_conf_t;


static ngx_http_module_t  ngx_http_hsts_module_ctx = {
  NULL,                    /* preconfiguration */
  ngx_http_hsts_init,           /* postconfiguration */

  NULL,                    /* create main configuration */
  NULL,                    /* init main configuration */

  NULL,                    /* create server configuration */
  NULL,                    /* merge server configuration */

  ngx_http_hsts_create_loc_conf,                    /* create location configuration */
  ngx_http_hsts_merge_loc_conf                     /* merge location configuration */
};


static ngx_command_t ngx_http_hsts_commands[] = {
    { ngx_string("hsts"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE12,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hsts_loc_conf_t, expires),
      NULL },
    ngx_null_command
};


ngx_module_t  ngx_http_hsts_module = {
  NGX_MODULE_V1,
  &ngx_http_hsts_module_ctx,  /* module context */
  ngx_http_hsts_commands,                            /* module directives */
  NGX_HTTP_MODULE,                 /* module type */
  NULL,                            /* init master */
  NULL,                            /* init module */
  NULL,                            /* init process */
  NULL,                            /* init thread */
  NULL,                            /* exit thread */
  NULL,                            /* exit process */
  NULL,                            /* exit master */
  NGX_MODULE_V1_PADDING
};

static void *ngx_http_hsts_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_hsts_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hsts_loc_conf_t));
  if (conf == NULL) {
      return NULL;
  }

  return conf;
}


static char *ngx_http_hsts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_hsts_loc_conf_t *prev = parent;
  ngx_http_hsts_loc_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->expires, prev->expires, "")

  if (conf->expires.len > 0) {
    char* expires = malloc(conf->expires.len + 1);
    ngx_memcpy(expires, conf->expires.data, conf->expires.len);

    struct tm tm;
    if (strptime(expires, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
      free(expires);

      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
      return NGX_CONF_ERROR;
    }

    free(expires);

    conf->expires_time = timegm(&tm);

    if (conf->expires_time == -1) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid expire date");
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_hsts_init(ngx_conf_t *cf) {
  ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);

  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_hsts_handler;

  return NGX_OK;
}

static ngx_int_t ngx_http_hsts_handler(ngx_http_request_t *r) {
  if (r->internal) {
    return NGX_DECLINED;
  }

  ngx_table_elt_t* h = ngx_list_push(&r->headers_out.headers);

  if (h == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_http_hsts_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_hsts_module);

  if (conf->expires_time == 0) {
    return NGX_DECLINED;
  }

  char *val = ngx_palloc(r->pool, 32);
  if (val == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  size_t hvallen = snprintf(val, 32, "max-age=%ld; includeSubdomains", conf->expires_time - time(0));

  ngx_table_elt_t *info_header = ngx_list_push(&r->headers_out.headers);
  if (info_header == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  info_header->hash = 1;
  ngx_str_set(&info_header->key, "Strict-Transport-Security");

  ngx_str_t hval;
  hval.len = hvallen;
  hval.data = (u_char*)val;

  info_header->value = hval;

  return NGX_DECLINED;
}

