#include <stdio.h>
#include <inttypes.h>

#include "terastream.h"
#include "adiag_functions.h"
#include "provisioning.h"
#include "common.h"

const char *YANG_MODEL = "ietf-interfaces";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    char *ucipath;
    char *xpath;
} sr_uci_link;

static sr_uci_link table_sr_uci[] =
{
    { "network.wan.mtu", "/ietf-interfaces:interfaces/interface[name='wan']/ietf-ip:ipv6/mtu" },
    /* { "network.wan.ipaddr", "/ietf-interfaces:interfaces/interface[name='wan']/ietf-ip:ipv6/address" }, */
};

/* Mappings of operational nodes to corresponding handler functions. */
/* Functions must not need the plugin context. */
static adiag_node_func_m table_operational[] = {
    { "cpu-usage", adiag_cpu_usage },
    { "memory-status", adiag_free_memory },
};


static const struct rpc_method table_rpc[] = {
    { "cpe-update", prov_cpe_update },
    { "cpe-reboot", prov_cpe_reboot },
    { "cpe-factory-reset", prov_factory_reset },
};

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(struct plugin_ctx *pctx, sr_session_ctx_t *sess);

/* Update startup datastore configuration from UCI configuration file values. */
static int config_uci_to_store(struct plugin_ctx *pctx, sr_session_ctx_t *sess);

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);

static int
get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
    int rc = UCI_OK;
    char path[MAX_UCI_PATH];
    struct uci_ptr ptr;

    sprintf(path, "%s", ucipath);
    INF("%s %s", path, *value);

    rc = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

    strcpy(*value, ptr.o->v.string);

  exit:
    return rc;
}

static int
set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
    int rc = UCI_OK;
    struct uci_ptr ptr;
    char *set_path = calloc(1, MAX_UCI_PATH);

    sprintf(set_path, "%s%s%s", ucipath, "=", value);

    rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

    rc = uci_set(uctx, &ptr);
    UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

    rc = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(rc, exit, "uci_save %d %s", rc, set_path);

    rc = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(rc, exit, "uci_commit %d %s", rc, set_path);

  exit:
    free(set_path);

    return rc;
}

static int
config_xpath_to_ucipath(struct plugin_ctx *pctx, sr_session_ctx_t *sess, char *xpath, char *ucipath)
{
    char *val_str;
    sr_val_t *val = NULL;
    int rc = SR_ERR_OK;

    rc = sr_get_item(sess, xpath, &val);
    SR_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

    val_str = sr_val_to_str(val);
    SR_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

    rc = set_uci_item(pctx->uctx, ucipath, val_str);
    UCI_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

  exit:
    return rc;
}

static int
config_ucipath_to_xpath(struct plugin_ctx *pctx, sr_session_ctx_t *sess, char *ucipath, char *xpath)
{
    char *uci_val = calloc(1, 100);
    int rc = SR_ERR_OK;

    rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
    UCI_CHECK_RET(rc, exit, "get_uci_item %s", sr_strerror(rc));

    rc = sr_set_item_str(sess, xpath, uci_val, SR_EDIT_DEFAULT);
    SR_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

 exit:
    if (uci_val) {
        free(uci_val);
    }

    return rc;
}

static int
config_store_to_uci(struct plugin_ctx *pctx, sr_session_ctx_t *sess)
{
    /* Read Sysrepo configuration. */
    /* for (xpath, ucipath) in table_sr_uci */
    char *xpath = NULL;
    char *ucipath = NULL;
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    for (int i = 0; i < n_mappings; i++) {
        xpath = table_sr_uci[i].xpath;
        ucipath = table_sr_uci[i].ucipath;
        rc = config_xpath_to_ucipath(pctx, sess, xpath, ucipath);
        UCI_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc));
        SR_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc));
    }

  exit:
    return rc;
}

static int
config_uci_to_store(struct plugin_ctx *pctx, sr_session_ctx_t *sess)
{
    char *xpath = NULL;
    char *ucipath = NULL;
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    /* Read UCI configuration. */
    for (int i = 0; i < n_mappings; i++) {

        xpath = table_sr_uci[i].xpath;
        ucipath = table_sr_uci[i].ucipath;
        fprintf(stderr, "xpath,ucipath : %s, %s\n", xpath, ucipath);

        rc = config_ucipath_to_xpath(pctx, sess, ucipath, xpath);
        UCI_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc));
        SR_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc));
    }

  exit:
    return rc;
}

/* Device diagnostics part. */
/* SIP diagnostics - will need device for that ... */
/* libnl stuff ... */
/* prefix: diag_ */

/* Advanced diagnostics. */
/* prefix: adiag_ */

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int rc = SR_ERR_OK;
    struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx;

    rc = config_store_to_uci(pctx, session);

    return rc;
}

static int
data_provider_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char *node;
    adiag_func func;
    sr_val_t *val;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    (void) pctx;
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    /* diagnostics */

    /* advanced diagnostics */
    for (int i = 0; i < n_mappings; i++) {
        node = table_operational[i].node;
        func = table_operational[i].op_func;

        if (sr_xpath_node_name_eq(cb_xpath, node)) {
            *values_cnt = 1;
            rc = sr_new_values(*values_cnt, &val);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            rc = func(val);

            *values = val;
        }
    }

    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream");

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }

    /* operational data */
    rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", data_provider_cb, *private_ctx,
                                   SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_dp_get_items_subscribe: %s\n", sr_strerror(rc));
        goto error;
    }

    *private_ctx = ctx;

    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    rc = config_uci_to_store(ctx, session);
    SR_CHECK_RET(rc, error, "initial uci to store error: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream finished.");

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    sr_unsubscribe(session, ctx->subscription);
    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(__attribute__((unused)) int signum) {
	INF_MSG("Sigint called, exiting...");
	exit_application = 1;
}

int
main() {
	INF_MSG("Plugin application mode initialized");
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_ctx = NULL;
	int rc = SR_ERR_OK;

	/* connect to sysrepo */
	rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
	SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

	/* start session */
	rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
	SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

	rc = sr_plugin_init_cb(session, &private_ctx);
	SR_CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);  /* or do some more useful work... */
	}

	sr_plugin_cleanup_cb(session, private_ctx);
cleanup:
	if (NULL != session) {
		sr_session_stop(session);
	}
	if (NULL != connection) {
		sr_disconnect(connection);
	}
}
#endif
