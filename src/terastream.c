#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "terastream.h"
#include "network.h"
#include "adiag_functions.h"
#include "common.h"

const char *YANG_MODEL = "ietf-interfaces";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    char *default_value;
    char ucipath[MAX_UCI_PATH];
    char xpath[MAX_XPATH];
} sr_uci_link;

/* Mappings of uci options to Sysrepo xpaths. */
static sr_uci_link table_sr_uci[] =
{
    { "1500", "network.%s.mtu",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/mtu" },
    { "1500", "network.%s.mtu",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/mtu" },

    { "24", "network.%s.ipaddr",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length" },
    { "64", "network.%s.ip6addr",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length" },
};

static const char *xpath_network_type_format = "/ietf-interfaces:interfaces/interface[name='%s']/type";
static const char *default_interface_type = "iana-if-type:ethernetCsmacd";

/* Mappings of operational nodes to corresponding handler functions. */
/* Functions must not need the plugin context. */
static adiag_node_func_m table_operational[] = {
  { "version", adiag_version },
  { "memory-status", adiag_free_memory },
  { "cpu-usage", adiag_cpu_usage },
};

static oper_mapping table_interface_status[] = {
  { "oper-status", network_operational_operstatus },
  { "phys-address", network_operational_mac },
  { "out-octets", network_operational_rx },
  { "in-octets", network_operational_tx },
  { "mtu", network_operational_mtu },
  { "ip", network_operational_ip },
  { "neighbor", network_operational_neigh },
  { "rx-pwr", sfp_rx_pwr },
  { "tx-pwr", sfp_tx_pwr },
  { "voltage", sfp_voltage },
  { "current", sfp_current },
};

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(struct plugin_ctx *pctx, sr_val_t *value);

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);

static bool
val_has_data(sr_type_t type) {
    /* types containing some data */
    if (type == SR_BINARY_T) return true;
    else if (type == SR_BITS_T) return true;
    else if (type == SR_BOOL_T) return true;
    else if (type == SR_DECIMAL64_T) return true;
    else if (type == SR_ENUM_T) return true;
    else if (type == SR_IDENTITYREF_T) return true;
    else if (type == SR_INSTANCEID_T) return true;
    else if (type == SR_INT8_T) return true;
    else if (type == SR_INT16_T) return true;
    else if (type == SR_INT32_T) return true;
    else if (type == SR_INT64_T) return true;
    else if (type == SR_STRING_T) return true;
    else if (type == SR_UINT8_T) return true;
    else if (type == SR_UINT16_T) return true;
    else if (type == SR_UINT32_T) return true;
    else if (type == SR_UINT64_T) return true;
    else if (type == SR_ANYXML_T) return true;
    else if (type == SR_ANYDATA_T) return true;
    else return false;
}

static char *
get_key_value(char *orig_xpath, int n)
{
  char *key = NULL, *node = NULL, *xpath = NULL, *val = NULL;
  sr_xpath_ctx_t state = {0,0,0,0};

  xpath = strdup(orig_xpath);
  node = sr_xpath_next_node(xpath, &state);
  if (NULL == node) {
    goto error;
  }
  int counter = 0;
  while(true) {
    key = sr_xpath_next_key_name(NULL, &state);
    if (NULL != key) {
      val = sr_xpath_next_key_value(NULL, &state);
      if (counter++ == n) break;
      /* break; */
    }
    node = sr_xpath_next_node(NULL, &state);
    if (NULL == node) {
      break;
    }
  }

 error:
  if (NULL != xpath) {
    free(xpath);
  }
  return key ? strdup(val) : NULL;
}

static int
get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
  int rc = UCI_OK;
  char path[MAX_UCI_PATH];
  struct uci_ptr ptr;

  sprintf(path, "%s", ucipath);
  rc = uci_lookup_ptr(uctx, &ptr, path, true);
  UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

  if (ptr.o == NULL) {
      return UCI_ERR_NOTFOUND;
  }

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
config_xpath_to_ucipath(struct plugin_ctx *pctx, sr_uci_link *mapping, sr_val_t *value)
{
    char *val_str = NULL;
    char ucipath[MAX_UCI_PATH] ;
    char xpath[MAX_XPATH];
    int rc = SR_ERR_OK;
    char *device_name = get_key_value(value->xpath, 0);

    if (!device_name) goto exit;

    sprintf(xpath, mapping->xpath, device_name);

    val_str = sr_val_to_str(value);
    if (NULL == val_str) {
        val_str = strdup(mapping->default_value);
    }

    sprintf(ucipath, mapping->ucipath, device_name);
    rc = set_uci_item(pctx->uctx, ucipath, val_str);
    UCI_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

    free(val_str);
    free(device_name);

  exit:
    return rc;
}

static int
config_store_to_uci(struct plugin_ctx *pctx, sr_val_t *value)
{
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    if (false == val_has_data(value->type)) {
        return SR_ERR_OK;
    }

    for (int i = 0; i < n_mappings; i++) {
        if (0 == strcmp(sr_xpath_node_name(value->xpath), sr_xpath_node_name(table_sr_uci[i].xpath))) {
            rc = config_xpath_to_ucipath(pctx, &table_sr_uci[i], value);
            INF("Failed to map xpath to ucipath: %s", sr_strerror(rc));
        }
    }

    return SR_ERR_OK;
}

/* Given name of the UCI interface, fill 'ietf-interfaces' interface.
 * Default mandatory type is also added first.
*/
static int
add_interface(struct plugin_ctx *pctx, sr_session_ctx_t *session, char *name)
{
    char xpath[MAX_XPATH];
    char ucipath[MAX_UCI_PATH];
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc;

    sprintf(xpath, xpath_network_type_format, name);
    rc = sr_set_item_str(session,
                         xpath,
                         default_interface_type,
                         SR_EDIT_DEFAULT);
    SR_CHECK_RET(rc, error, "Couldn't add type for interface %s: %s", xpath, sr_strerror(rc));

    for (size_t i = 0; i < n_mappings; i++) {

        char *uci_val = calloc(1, MAX_UCI_PATH);

        /* get ip */
        snprintf(ucipath, MAX_UCI_PATH, table_sr_uci[i].ucipath, name);
        rc = get_uci_item(pctx->uctx, ucipath, &uci_val);

        /* Find interface name and ip. */
        if (strstr(table_sr_uci[i].xpath, "address")) {
            if (UCI_ERR_NOTFOUND == rc) {
                rc = SR_ERR_OK;
                continue;
            }

            sprintf(xpath, table_sr_uci[i].xpath, name, uci_val);
            uci_val = strdup(table_sr_uci[i].default_value);

        } else {                /* Only need ip. */
           if (UCI_OK != rc) {
                uci_val = strdup(table_sr_uci[i].default_value);
                INF("Using default %s", uci_val);
                if (!strcmp("", uci_val)) {
                    INF("No default %s", "continue!");
                    rc = SR_ERR_OK;
                    continue;
                }
            }
            sprintf(xpath, table_sr_uci[i].xpath, name);
        }

        rc = sr_set_item_str(session,
                             xpath,
                             uci_val,
                             SR_EDIT_DEFAULT);
        INF("%s: %s\t:%s", sr_strerror(rc), xpath, uci_val);
        rc = SR_ERR_OK;

        free(uci_val);
    }

  error:
    return rc;
}

static int
get_uci_interfaces(struct plugin_ctx *pctx)
{
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    int rc;

    rc = uci_load(pctx->uctx, "network", &package);

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("interface", type) == 0) {
            strcpy(pctx->interface_names[pctx->interface_count++], name);
        }
    }

    return rc;
}

/* Read current UCI network configuration into sysrepo datastore. */
static int
init_interfaces(struct plugin_ctx *pctx, sr_session_ctx_t *session)
{
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    int rc;

    rc = uci_load(pctx->uctx, "network", &package);

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("interface", type) == 0) {
            rc = add_interface(pctx, session, name);
            SR_CHECK_RET(rc, exit, "Couldn't add interface %s: %s", name, sr_strerror(rc));
        }
    }

    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

  exit:
    return rc;
}

static void
restart_network(int wait_time)
{
    pid_t restart_pid;

    restart_pid = fork();
    if (restart_pid > 0) {
        INF("[pid=%d] Restarting network in %d seconds after module is changed.", restart_pid, wait_time);
        sleep(wait_time);
        execv("/etc/init.d/network", (char *[]){ "/etc/init.d/network", "restart", NULL });
        exit(0);
    } else {
        INF("[pid=%d] Could not execute network restart, do it manually?", restart_pid);
    }
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx;
    int rc = SR_ERR_OK;

    /* Cover other events: ABORT */
    if (SR_EV_APPLY == event) {
        INF("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: %s ==========\n\n", module_name);
        rc = sr_copy_config(pctx->startup_session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
        /* print_current_config(session, module_name); */
    } else {
        INF("Some insignificant event %d", event);
        return SR_ERR_OK;
    }

    sr_change_iter_t *it = NULL;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[MAX_XPATH] = {0,};

    snprintf(change_path, MAX_XPATH, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", change_path);
        return rc;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                &oper, &old_value, &new_value))) {
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = config_store_to_uci(pctx, new_value);
            sr_print_val(new_value);
        }

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    INF_MSG("\n\n ========== END OF CHANGES =======================================\n\n");

    if (SR_EV_VERIFY == event) {
        restart_network(2);
    }

    sr_free_change_iter(it);

    return rc;
}

static size_t
list_size(struct list_head *list)
{
    size_t current_size = 0;
    struct value_node *vn;

    list_for_each_entry(vn, list, head) {
        current_size += 1;
    }

    return current_size;
}

int
sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
{
    int rc = SR_ERR_OK;

    switch (source->type) {
        case SR_BINARY_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.binary_val);
            break;
        case SR_BITS_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.bits_val);
            break;
        case SR_ENUM_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.enum_val);
            break;
        case SR_IDENTITYREF_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.identityref_val);
            break;
        case SR_INSTANCEID_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.instanceid_val);
            break;
        case SR_STRING_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.string_val);
            break;
        case SR_BOOL_T:
        case SR_DECIMAL64_T:
        case SR_INT8_T:
        case SR_INT16_T:
        case SR_INT32_T:
        case SR_INT64_T:
        case SR_UINT8_T:
        case SR_UINT16_T:
        case SR_UINT32_T:
        case SR_UINT64_T:
        case SR_TREE_ITERATOR_T:
            dest->data = source->data;
            dest->type = source->type;
            break;
        default:
            dest->type = source->type;
            break;
    }

    sr_val_set_xpath(dest, source->xpath);
    return rc;
}


static int
data_provider_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char *node;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    (void) pctx;
    size_t n_mappings;
    int rc = SR_ERR_OK;

    /* INF("%s", cb_xpath); */

    if (sr_xpath_node_name_eq(cb_xpath, "provisioning:hgw-diagnostics")) {
        n_mappings = ARR_SIZE(table_operational);
        INF("Diagnostics for %s %zu", cb_xpath, n_mappings);

        adiag_func func;
        *values_cnt = n_mappings;
        rc = sr_new_values(*values_cnt, values);
        SR_CHECK_RET(rc, exit, "Couldn't create values %s", sr_strerror(rc));

        for (size_t i = 0; i < *values_cnt; i++) {
            node = table_operational[i].node;
            func = table_operational[i].op_func;
            INF("\tDiagnostics for: %s", node);

            rc = func(&(*values)[i]);
            /* INF("[%d] %s", rc, sr_val_to_str(&(*values)[i])); */
        }

    }

    struct list_head list = LIST_HEAD_INIT(list);
    if (sr_xpath_node_name_eq(cb_xpath, "interface")) {
        oper_func func;
        n_mappings = ARR_SIZE(table_interface_status);

        network_operational_start();

        for (size_t i = 0; i < n_mappings; i++) {
            node = table_interface_status[i].node;
            func = table_interface_status[i].op_func;

            for (size_t j = 0; j < pctx->interface_count; j++) {
              rc = func(pctx->interface_names[j], &list);
              /* INF("%s", sr_strerror((rc))); */
            }
        }

        size_t cnt = 0;
        cnt = list_size(&list);
        INF("Allocating %zu values.", cnt);

        struct value_node *vn, *q;
        size_t j = 0;
        rc = sr_new_values(cnt, values);
        INF("%s", sr_strerror(rc));

        list_for_each_entry_safe(vn, q, &list, head) {
            rc = sr_dup_val_data(&(*values)[j], vn->value);
            SR_CHECK_RET(rc, exit, "Couldn't copy value: %s", sr_strerror(rc));
            j += 1;
            sr_free_val(vn->value);
            list_del(&vn->head);
            free(vn);
        }

        *values_cnt = cnt;

        list_del(&list);
    }

    if (*values_cnt > 0) {
        INF("Debug sysrepo values printout: %zu", *values_cnt);
        for (size_t i = 0; i < *values_cnt; i++){
                     sr_print_val(&(*values)[i]);
        }
    }

  exit:
    return rc;
}


static int
sync_datastores(struct plugin_ctx *ctx)
{
    char startup_file[MAX_XPATH] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, MAX_XPATH, "/etc/sysrepo/data/%s.startup", YANG_MODEL);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = init_interfaces(ctx, ctx->startup_session);
        INF_MSG("copy uci data to sysrepo");
        SR_CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        SR_CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

  error:
    return rc;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc = SR_ERR_OK;
    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream");

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }

    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->startup_connection);
    SR_CHECK_RET(rc, error, "Error by sr_connect: %s", sr_strerror(rc));

    rc = sr_session_start(ctx->startup_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->startup_session);
    SR_CHECK_RET(rc, error, "Error by sr_session_start: %s", sr_strerror(rc));

    *private_ctx = ctx;

    /* Init type for interface... */
    rc = sync_datastores(ctx);
    SR_CHECK_RET(rc, error, "Couldn't initialize datastores: %s", sr_strerror(rc));

    rc= get_uci_interfaces(ctx);
    SR_CHECK_RET(rc, error, "Couldn't initialize uci interfaces: %s", sr_strerror(rc));

    /* rc = sr_copy_config(ctx->startup_session, YANG_MODEL, SR_DS_STARTUP, SR_DS_RUNNING); */
    /* INF("%s", sr_strerror(rc)); */

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream");
    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &ctx->subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to diagnostics");
    rc = sr_dp_get_items_subscribe(session, "/provisioning:hgw-diagnostics", data_provider_cb, *private_ctx,
                                   SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    INF("sr_plugin_init_cb for sysrepo-plugin-dt-terastream %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to operational data");
    rc = sr_dp_get_items_subscribe(session,
                                   "/ietf-interfaces:interfaces-state",
                                   data_provider_cb, *private_ctx,
                                   SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    for (size_t i = 0; i < ctx->interface_count; i++) {
      INF("[%zu/%zu] %s", i+1, ctx->interface_count, ctx->interface_names[i]);
    }
    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream finished.");

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    if (NULL != ctx->subscription) {
        sr_unsubscribe(session, ctx->subscription);
    }
    if (NULL != ctx->startup_session) {
        sr_session_stop(ctx->startup_session);
    }
    if (NULL != ctx->startup_connection) {
        sr_disconnect(ctx->startup_connection);
    }
    if (NULL != ctx->uctx) {
        uci_free_context(ctx->uctx);
    }
    network_operational_stop();
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
    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
    SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    INF_MSG("Initializing plugin ...");
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
