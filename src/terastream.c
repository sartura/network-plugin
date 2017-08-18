#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "terastream.h"
#include "network.h"
#include "adiag_functions.h"
#include "provisioning.h"
#include "common.h"

const char *YANG_MODEL = "ietf-interfaces";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
  char *ucipath;
  char *xpath;
} sr_uci_link;

/* Mappings of uci options to Sysrepo xpaths. */
static sr_uci_link table_sr_uci[] =
{
  { "network.wan.mtu", "/ietf-interfaces:interfaces/interface[name='wan']/ietf-ip:ipv4/mtu" },
  { "network.wan6.mtu", "/ietf-interfaces:interfaces/interface[name='wan6']/ietf-ip:ipv6/mtu" },
  /* { "network.wan.ipaddr", "/ietf-interfaces:interfaces/interface[name='wan']/ietf-ip:ipv6/address" }, */

  /* wireless */
  {"wireless.%s.type", "/wireless:devices/device[name='%s']/type"},
  {"wireless.%s.country", "/wireless:devices/device[name='%s']/country"},
  {"wireless.%s.band", "/wireless:devices/device[name='%s']/band"},
  {"wireless.%s.bandwidth", "/wireless:devices/device[name='%s']/bandwidth"},
  {"wireless.%s.scantimer", "/wireless:devices/device[name='%s']/scantimer"},
  {"wireless.%s.wmm", "/wireless:devices/device[name='%s']/wmm"},
  {"wireless.%s.wmm_noack",  "/wireless:devices/device[name='%s']/wmm_noack"},

  {"wireless.%s.wmm_apsd","/wireless:devices/device[name='%s']/type" },
  {"wireless.%s.txpower", "/wireless:devices/device[name='%s']/txpower"},
  {"wireless.%s.rateset", "/wireless:devices/device[name='%s']/rateset"},
  {"wireless.%s.frag", "/wireless:devices/device[name='%s']/frag"},
  {"wireless.%s.rts", "/wireless:devices/device[name='%s']/rts"},
  {"wireless.%s.dtim_period", "/wireless:devices/device[name='%s']/dtim_period"},
  {"wireless.%s.beacon_int", "/wireless:devices/device[name='%s']/beacon_int"},
  {"wireless.%s.rxchainps", "/wireless:devices/device[name='%s']/rxchainps"},
  {"wireless.%s.rxchainps_qt", "/wireless:devices/device[name='%s']/rxchainps_qt"},
  {"wireless.%s.rxchainps_pps", "/wireless:devices/device[name='%s']/rxchainps_pps"},
  {"wireless.%s.rifs", "/wireless:devices/device[name='%s']/rifs"},
  {"wireless.%s.rifs_advert", "/wireless:devices/device[name='%s']/rifs_advert"},
  {"wireless.%s.maxassoc", "/wireless:devices/device[name='%s']/maxassoc"},
  {"wireless.%s.beamforming", "/wireless:devices/device[name='%s']/beamforming"},
  {"wireless.%s.doth", "/wireless:devices/device[name='%s']/doth"},
  {"wireless.%s.dfsc", "/wireless:devices/device[name='%s']/dfsc"},
  {"wireless.%s.channel", "/wireless:devices/device[name='%s']/channel"},
  {"wireless.%s.disabled", "/wireless:devices/device[name='%s']/disabled"},
  {"wireless.%s.hwmode", "/wireless:devices/device[name='%s']/hwmode"},

  {"wireless.@wifi-iface[0].device","/wireless:devices/device[name='wl0']/interface[ssid='%s']/device"},
  {"wireless.@wifi-iface[0].network", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/network"},
  {"wireless.@wifi-iface[0].mode", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/mode"},
  {"wireless.@wifi-iface[0].encryption", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/encryption"},
  {"wireless.@wifi-iface[0].cipher", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/cipher"},
  {"wireless.@wifi-iface[0].key", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/key"},
  {"wireless.@wifi-iface[0].gtk_rekey", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/gtk_rekey"},
  {"wireless.@wifi-iface[0].macfilter", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/macfilter"},
  {"wireless.@wifi-iface[0].wps_pbc", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/wps_pbc"},
  {"wireless.@wifi-iface[0].wmf_bss_enable", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/wmf_bss_enable"},
  {"wireless.@wifi-iface[0].bss_max" , "/wireless:devices/device[name='wl0']/interface[ssid='%s']/bss_max"},
  {"wireless.@wifi-iface[0].ifname", "/wireless:devices/device[name='wl0']/interface[ssid='%s']/ifname"},

};

static const char *xpath_network_type_format = "/ietf-interfaces:interfaces/interface[name='%s']/type";

/* Mappings of operational nodes to corresponding handler functions. */
/* Functions must not need the plugin context. */
static adiag_node_func_m table_operational[] = {
  { "version", adiag_version },
  { "memory-status", adiag_free_memory },
  { "cpu-usage", adiag_cpu_usage },
};

/* Mappings of operational data nodes for provisioning functions to functions. */
static const struct rpc_method table_prov[] = {
  { "cpe-update", prov_cpe_update },
  { "cpe-reboot", prov_cpe_reboot },
  { "cpe-factory-reset", prov_factory_reset },
};

static adiag_node_func_m table_interface_status[] = {
  { "oper-status", network_operational_operstatus },
  { "phys-address", network_operational_mac },
  { "out-octets", network_operational_rx },
  { "in-octets", network_operational_tx },
  { "mtu", network_operational_mtu },
  { "ip", network_operational_ip },
  /* { "neighbor", network_operational_neigh }, */
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
config_xpath_to_ucipath(struct plugin_ctx *pctx, sr_session_ctx_t *sess, char *xpath, char *ucipath)
{
  char *val_str;
  sr_val_t *val = NULL;
  int rc = SR_ERR_OK;

  rc = sr_get_item(sess, xpath, &val);
  /* SR_CHECK_RET(rc, exit, "sr_get_item %s for xpath %s", sr_strerror(rc), xpath); */

  if (SR_ERR_OK == rc) {
      val_str = sr_val_to_str(val);
      SR_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

      rc = set_uci_item(pctx->uctx, ucipath, val_str);
      UCI_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));
  }

exit:
  return rc;
}

static int
config_ucipath_to_xpath(struct plugin_ctx *pctx, sr_session_ctx_t *sess, char *ucipath, char *xpath)
{
  char *uci_val = calloc(1, 100);
  int rc = SR_ERR_OK;

  rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
  /* UCI_CHECK_RET(rc, exit, "get_uci_item %s", sr_strerror(rc)); */
  if (UCI_OK == rc) {
      INF("xpath %s -> ucival %s", xpath, uci_val);
      rc = sr_set_item_str(sess, xpath, uci_val, SR_EDIT_DEFAULT);
      SR_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));
  }

  INF("Set %s to %s", xpath, uci_val);

  return SR_ERR_OK;

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
        INF("xpath_to_ucipath [%d] %s", rc, sr_strerror(rc));
        /* UCI_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc)); */
        /* SR_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc)); */
    }

  /* exit: */
    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }

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
        INF("fail %s", sr_strerror(rc));
        /* UCI_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc)); */
        /* SR_CHECK_RET(rc, exit, "config_ucipath_to_xpath %s", sr_strerror(rc)); */
    }

    rc = sr_commit(sess);

  /* exit: */
    return rc;
}

static int
add_interface(sr_session_ctx_t *session, char *name)
{
    char xpath[100];
    int rc;

    /* Init type for interface... */
    sprintf(xpath, xpath_network_type_format, name);
    INF("xpath: %s", xpath);
    rc = sr_set_item_str(session,
                         xpath,
                         "iana-if-type:ethernetCsmacd",
                         SR_EDIT_DEFAULT);

    return rc;
}

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

        INF("adding interface %s %s", type, name);
        if (strcmp("interface", type) == 0) {
            add_interface(session, name);
        }
    }

    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

    /* rc = config_uci_to_store(pctx, session); */
    /* SR_CHECK_RET(rc, exit, "Couldn't initialize interfaces: %s", sr_strerror(rc)); */

  exit:
    return rc;
}


static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int rc = SR_ERR_OK;
    /* struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx; */

    /* rc = config_store_to_uci(pctx, session); */
    INF("module changed %s %s", module_name, sr_strerror(rc));

    return SR_ERR_OK;
}

#define WIRELESS_DEVICE_NAME_LENGTH 20

typedef struct int_string_tuple_s {
    size_t index;
    char *string;
} int_string_tuple;

static int_string_tuple table_wireless_device_indices[] = {
    { 0, "wl0" },
    { 1, "wl1" },
};

static char *
get_key_value_nth(char *orig_xpath, int n)
{
    char *key = NULL, *node = NULL, *xpath = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    xpath = strdup(orig_xpath);

    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
        goto error;
    }
    while(true) {
        key = sr_xpath_next_key_name(NULL, &state);
        INF("key %s", key);
        if (NULL != key) {
            if (n > 0) {
                n = n - 1;
                continue;
            }
            key = sr_xpath_next_key_value(NULL, &state);
            break;
        }
        INF("node %s", node);
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

  error:
    if (NULL != xpath) {
        free(xpath);
    }
    return key ? strdup(key) : NULL;
}

static char *
get_key_value(char *orig_xpath)
{
    return get_key_value_nth(orig_xpath, 0);
}


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

static int
sysrepo_to_uci(struct uci_context *uctx, sr_val_t *new_val)
{
    char xpath[MAX_XPATH];
    char ucipath[MAX_UCI_PATH];
    char *key = NULL;
    int rc = SR_ERR_OK;

    if (val_has_data(new_val->type)) {
        key = get_key_value(new_val->xpath);
        if (key == NULL) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
    }

    const int n_mappings = ARR_SIZE(table_sr_uci);
    for (int i = 0; i < n_mappings; i++) {
        snprintf(xpath, MAX_XPATH, table_sr_uci[i].xpath, key);
        snprintf(ucipath, MAX_UCI_PATH, table_sr_uci[i].ucipath, key);
        if (0 == strncmp(xpath,new_val->xpath,strlen(xpath))) {
            char *mem = NULL;
            mem = sr_val_to_str(new_val);
            INF("Setting %s to %s", ucipath, mem);
            rc = set_uci_item(uctx, ucipath, mem);
            if(mem) free(mem);
            UCI_CHECK_RET(rc, uci_error, "get_uci_item %s", sr_strerror(rc));
        }
    }

    return SR_ERR_OK;
  error:
    INF("Failed %s", sr_strerror(rc));
    return rc;
  uci_error:
    return SR_ERR_INTERNAL;
}

static int
uci_to_sysrepo(sr_session_ctx_t *session, sr_val_t *value)
{
    int rc = SR_ERR_OK;


}

static int
wireless_index_of_device(char *device_name){
    for (size_t i = 0; i < ARR_SIZE(table_wireless_device_indices); i++) {
        if (strcmp(table_wireless_device_indices[i].string, device_name) == 0) {
            return i;
        }
    }

    return -1;
}

static char *
wireless_device_of_index(size_t device_index){
    for (size_t i = 0; i < ARR_SIZE(table_wireless_device_indices); i++) {
        if (table_wireless_device_indices[i].index == device_index) {
            return table_wireless_device_indices[i].string;
        }
    }

    return NULL;
}

static int
wireless_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx;

    if (SR_EV_APPLY == event) {
        INF("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: %s ==========\n\n", module_name);
        /* print_current_config(session, module_name); */
    } else {
        INF("Some insignificant event %d", event);
        return SR_ERR_OK;
    }

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[MAX_XPATH] = {0,};

    snprintf(change_path, MAX_XPATH, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", change_path);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                &oper, &old_value, &new_value))) {
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            sysrepo_to_uci(pctx->uctx, new_value);
        }

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    INF_MSG("\n\n ========== END OF CHANGES =======================================\n\n");

cleanup:
    sr_free_change_iter(it);

    return SR_ERR_OK;
}


static int
data_provider_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char *node;
    adiag_func func;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    (void) pctx;
    int n_mappings = ARR_SIZE(table_operational);
    int rc = SR_ERR_OK;

    INF("==Called path %s %s [n_map %d]", cb_xpath, sr_xpath_node_name(cb_xpath), n_mappings);

    if (sr_xpath_node_name_eq(cb_xpath, "provisioning:hgw-diagnostics")) {
        INF("Diagnostics for %s %d", cb_xpath, n_mappings);

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

    n_mappings = ARR_SIZE(table_interface_status);
    if (sr_xpath_node_name_eq(cb_xpath, "interface")) {
      INF("Diagnostics for %s %d", cb_xpath, n_mappings);

      *values_cnt = n_mappings;
      rc = sr_new_values(*values_cnt, values);
      SR_CHECK_RET(rc, exit, "Couldn't create values %s", sr_strerror(rc));

      for (size_t i = 0; i < *values_cnt; i++) {
        node = table_interface_status[i].node;
        func = table_interface_status[i].op_func;
        INF("\tDiagnostics for: %s", node);

        rc = func(&(*values)[i]);
        /* INF("[%d] %s", rc, sr_val_to_str(&(*values)[i])); */
      }
    }

    INF_MSG("Debug sysrepo values printout:")
    for (size_t i = 0; i < *values_cnt; i++){
        sr_print_val(&(*values)[i]);
    }

   exit:
    return rc;
}

static int
init_provisioning_cb(sr_session_ctx_t *session, sr_subscription_ctx_t *subscription)
{
    char path[MAX_XPATH];
    const int n_mappings = ARR_SIZE(table_prov);
    int rc = SR_ERR_OK;
    INF_MSG("Provisioning callbacks rpcs...");

    for (int i = 0; i < n_mappings; i++) {
        snprintf(path, MAX_XPATH, "/provisioning:%s", table_prov[i].name);
        INF("Subscribing rpc %s", path);
        rc = sr_rpc_subscribe(session, path, table_prov[i].method, NULL,
                              SR_SUBSCR_CTX_REUSE, &subscription);
        SR_CHECK_RET(rc, exit, "initialization of rpc handler: %s failed with: %s",
                     table_prov[i].name, sr_strerror(rc));
    }

  exit:
    return rc;
}

static int
init_wireless(struct plugin_ctx *pctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK;
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    char xpath[MAX_XPATH];
    char ucipath[MAX_UCI_PATH];

    rc = uci_load(pctx->uctx, "wireless", &package);


    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("wifi-device", type) == 0) {
            for (size_t i = 0; i < ARR_SIZE(table_sr_uci); i++) {
                char *uci_val = calloc(1, 100);

                snprintf(xpath, MAX_XPATH, table_sr_uci[i].xpath, name);
                snprintf(ucipath, MAX_UCI_PATH, table_sr_uci[i].ucipath, name);
                if (!strstr(ucipath, "wireless")) {
                    continue;
                }
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    continue;
                }
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                INF("Setting %s to %s", xpath, uci_val);
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
                free(uci_val);
            }
        }
    }


    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

  exit:
    return rc;
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

    *private_ctx = ctx;

    /* Operational data handling. */
    rc = sr_dp_get_items_subscribe(session, "/provisioning:hgw-diagnostics", data_provider_cb, *private_ctx,
                                   SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    INF("sr_plugin_init_cb for sysrepo-plugin-dt-terastream %s", sr_strerror(rc));

    /* Operational data handling. */
    rc = sr_dp_get_items_subscribe(session,
                                   "/ietf-interfaces:interfaces-state",
                                   data_provider_cb, *private_ctx,
                                   SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    /* RPC handlers. */
    rc = init_provisioning_cb(session, subscription);
    SR_CHECK_RET(rc, error, "init_rpc_cb %s", sr_strerror(rc));

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-terastream");
    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    INF_MSG("sr_plugin_init_cb for wireless");
    rc = sr_module_change_subscribe(session, "wireless", wireless_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));


    /* Init type for interface... */
    rc = init_interfaces(ctx, session);
    SR_CHECK_RET(rc, error, "Couldn't initialize interfaces: %s", sr_strerror(rc));

    /* Init wireless. */
    rc = init_wireless(ctx, session);
    SR_CHECK_RET(rc, error, "Couldn't initialize wirelessx: %s", sr_strerror(rc));


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
