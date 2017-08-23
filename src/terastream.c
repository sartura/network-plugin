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
    char *default_value;
    sr_type_t default_value_type;
    char *ucipath;
    char *xpath;
} sr_uci_link;


/* Mappings of uci options to Sysrepo xpaths. */
static sr_uci_link table_sr_uci[] =
{
    { "1500", SR_UINT16_T, "network.%s.mtu",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/mtu" },
    { "1500", SR_UINT16_T, "network.%s.mtu",
      "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/mtu" },

    /* { "24",  SR_UINT8_T, "network.%s.ipaddr", */
    /*   "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length" }, */
    /* { "64",  SR_UINT8_T, "network.%s.ipaddr", */
    /*   "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length" }, */


};

static sr_uci_link table_wireless[] = {
    /* wireless */
    { 0, SR_STRING_T, "wireless.%s.type", "/wireless:devices/device[name='%s']/type"},
    { 0, SR_STRING_T, "wireless.%s.country", "/wireless:devices/device[name='%s']/country"},
    { 0, SR_STRING_T, "wireless.%s.band", "/wireless:devices/device[name='%s']/band"},
    { 0, SR_INT32_T, "wireless.%s.bandwidth", "/wireless:devices/device[name='%s']/bandwidth"},
    { 0, SR_INT32_T, "wireless.%s.scantimer", "/wireless:devices/device[name='%s']/scantimer"},
    { 0, SR_INT32_T, "wireless.%s.wmm", "/wireless:devices/device[name='%s']/wmm"},
    { 0, SR_INT32_T, "wireless.%s.wmm_noack",  "/wireless:devices/device[name='%s']/wmm_noack"},
    { 0, SR_INT32_T, "wireless.%s.wmm_apsd","/wireless:devices/device[name='%s']/type" },
    { 0, SR_INT32_T, "wireless.%s.txpower", "/wireless:devices/device[name='%s']/txpower"},
    { 0, SR_STRING_T, "wireless.%s.rateset", "/wireless:devices/device[name='%s']/rateset"},
    { 0, SR_INT32_T, "wireless.%s.frag", "/wireless:devices/device[name='%s']/frag"},
    { 0, SR_INT32_T, "wireless.%s.rts", "/wireless:devices/device[name='%s']/rts"},
    { 0, SR_INT32_T, "wireless.%s.dtim_period", "/wireless:devices/device[name='%s']/dtim_period"},
    { 0, SR_INT32_T, "wireless.%s.beacon_int", "/wireless:devices/device[name='%s']/beacon_int"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps", "/wireless:devices/device[name='%s']/rxchainps"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps_qt", "/wireless:devices/device[name='%s']/rxchainps_qt"},
    { 0, SR_INT32_T, "wireless.%s.rxchainps_pps", "/wireless:devices/device[name='%s']/rxchainps_pps"},
    { 0, SR_INT32_T, "wireless.%s.rifs", "/wireless:devices/device[name='%s']/rifs"},
    { 0, SR_INT32_T, "wireless.%s.rifs_advert", "/wireless:devices/device[name='%s']/rifs_advert"},
    { 0, SR_INT32_T, "wireless.%s.maxassoc", "/wireless:devices/device[name='%s']/maxassoc"},
    { 0, SR_INT32_T, "wireless.%s.beamforming", "/wireless:devices/device[name='%s']/beamforming"},
    { 0, SR_INT32_T, "wireless.%s.doth", "/wireless:devices/device[name='%s']/doth"},
    { 0, SR_INT32_T, "wireless.%s.dfsc", "/wireless:devices/device[name='%s']/dfsc"},
    { 0, SR_STRING_T, "wireless.%s.channel", "/wireless:devices/device[name='%s']/channel"},
    { 0, SR_INT32_T, "wireless.%s.disabled", "/wireless:devices/device[name='%s']/disabled"},
    { 0, SR_STRING_T, "wireless.%s.hwmode", "/wireless:devices/device[name='%s']/hwmode"},

    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].ssid",
      "/wireless:devices/device[name='%s']/interface[ssid='%s']/ssid"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].device",
      "/wireless:devices/device[name='%s']/interface[ssid='%s']/device"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].network", "/wireless:devices/device[name='%s']/interface[ssid='%s']/network"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].mode", "/wireless:devices/device[name='%s']/interface[ssid='%s']/mode"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].encryption", "/wireless:devices/device[name='%s']/interface[ssid='%s']/encryption"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].cipher", "/wireless:devices/device[name='%s']/interface[ssid='%s']/cipher"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].key", "/wireless:devices/device[name='%s']/interface[ssid='%s']/key"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].gtk_rekey", "/wireless:devices/device[name='%s']/interface[ssid='%s']/gtk_rekey"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].macfilter", "/wireless:devices/device[name='%s']/interface[ssid='%s']/macfilter"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].wps_pbc", "/wireless:devices/device[name='%s']/interface[ssid='%s']/wps_pbc"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].wmf_bss_enable", "/wireless:devices/device[name='%s']/interface[ssid='%s']/wmf_bss_enable"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].bss_max" , "/wireless:devices/device[name='%s']/interface[ssid='%s']/bss_max"},
    { 0, SR_STRING_T, "wireless.@wifi-iface[%d].ifname", "/wireless:devices/device[name='%s']/interface[ssid='%s']/ifname"},

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

const char *index_fmt = "/wireless:devices/device[name='%s']/interface[ssid='%s']/index";

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(struct plugin_ctx *pctx, sr_session_ctx_t *sess, sr_val_t *value);

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
get_key_value_second(char *orig_xpath)
{
  char *key = NULL, *node = NULL, *xpath = NULL, *val = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    xpath = strdup(orig_xpath);

    char *cur = strstr(xpath, "ssid");
    if (!cur) {
      return NULL;
    }

    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
      goto error;
    }
    int counter = 0;
    while(true) {
      key = sr_xpath_next_key_name(NULL, &state);
      if (NULL != key) {
        val = sr_xpath_next_key_value(NULL, &state);
        if (++counter == 2) break;
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

static char *
get_key_value(char *orig_xpath)
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
        if (NULL != key) {
            key = sr_xpath_next_key_value(NULL, &state);
            break;
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
    return key ? strdup(key) : NULL;
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
config_xpath_to_ucipath(struct plugin_ctx *pctx, sr_session_ctx_t *sess, sr_uci_link *mapping, sr_val_t *value)
{
    char *val_str;
    char ucipath[MAX_UCI_PATH] ;
    char xpath[MAX_XPATH];
    sr_val_t *val = NULL;
    int rc = SR_ERR_OK;
    char *device_name = get_key_value(value->xpath);

    sprintf(xpath, mapping->xpath, device_name);

    rc = sr_get_item(sess, xpath, &val);
    SR_CHECK_RET(rc, exit, "sr_get_item %s for xpath %s", sr_strerror(rc), xpath);

    val_str = SR_ERR_NOT_FOUND == rc ? mapping->default_value : sr_val_to_str(val);
    if (NULL == val_str) {
        goto exit;
    }

    sprintf(ucipath, mapping->ucipath, device_name);
    rc = set_uci_item(pctx->uctx, ucipath, val_str);
    UCI_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

  exit:
    return rc;
}

static int
config_store_to_uci(struct plugin_ctx *pctx, sr_session_ctx_t *sess, sr_val_t *value)
{
  const int n_mappings = ARR_SIZE(table_sr_uci);
  int rc = SR_ERR_OK;

  for (int i = 0; i < n_mappings; i++) {
      if (false == val_has_data(value->type)) {
          continue;
      }
      rc = config_xpath_to_ucipath(pctx, sess, &table_sr_uci[i], value);
    }

  /* exit: */
    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }

    return rc;
}

static int
add_interface(struct plugin_ctx *pctx, sr_session_ctx_t *session, char *name)
{
    char xpath[MAX_XPATH];
    char ucipath[MAX_UCI_PATH];
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc;

    /* Init type for interface... */
    sprintf(xpath, xpath_network_type_format, name);
    rc = sr_set_item_str(session,
                         xpath,
                         "iana-if-type:ethernetCsmacd",
                         SR_EDIT_DEFAULT);
    SR_CHECK_RET(rc, error, "Couldn't add type for interface %s: %s", xpath, sr_strerror(rc));

    for (size_t i = 0; i < n_mappings; i++) {

        char *uci_val = calloc(1, 100);

        if (strstr(table_sr_uci[i].xpath, "address")) {
            /* get ip */
            snprintf(ucipath, MAX_UCI_PATH, table_sr_uci[i].ucipath, name);
            rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
            /* INF("%s\t%d: %s", ucipath, rc, uci_val); */
            if (UCI_ERR_NOTFOUND == rc) {
                rc = SR_ERR_OK;
                continue;
            }

            sprintf(xpath, table_sr_uci[i].xpath, name, uci_val);
            uci_val = strdup(table_sr_uci[i].default_value);
        } else {
            snprintf(ucipath, MAX_UCI_PATH, table_sr_uci[i].ucipath, name);
            rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
            INF("%s\t%d: %s", ucipath, rc, uci_val);
            if (UCI_OK != rc) {
                free(uci_val);
                uci_val = table_sr_uci[i].default_value;
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
        SR_CHECK_RET(rc, error, "Couldn't add interface %s with value: %s\t%s", xpath, uci_val, sr_strerror(rc));

        INF("[%d] Added value %s = %s", rc, xpath, uci_val);
        free(uci_val);
    }

  error:
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

        if (strcmp("interface", type) == 0) {
            rc = add_interface(pctx, session, name);
            SR_CHECK_RET(rc, exit, "Couldn't add interface %s: %s", name, sr_strerror(rc));
        }
    }

    INF("Got out of addinterface %d", rc);
    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

  exit:
    return rc;
}


static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
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
        return rc;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                &oper, &old_value, &new_value))) {
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = config_store_to_uci(pctx, session, new_value);
            sr_print_val(new_value);
        }

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    INF_MSG("\n\n ========== END OF CHANGES =======================================\n\n");


    return SR_ERR_OK;
}

#define WIRELESS_DEVICE_NAME_LENGTH 20

typedef struct int_string_tuple_s {
    size_t index;
    char *string;
} int_string_tuple;


struct wireless_device {
    char *name, *option;
};

struct wireless_interface {
    int32_t index;
    char *option;
};

static int
wireless_xpath_to_device(char *orig_xpath, struct wireless_device *dev) {
    char *key = NULL, *node = NULL, *xpath = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    xpath = strdup(orig_xpath);

    node = sr_xpath_next_node(xpath, &state);
    if (NULL == node) {
        goto error;
    }

    while(true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            key = sr_xpath_next_key_value(NULL, &state);
            dev->name = strdup(key);
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

    sr_xpath_recover(&state);
    dev->option = sr_xpath_last_node(xpath, &state);

    return SR_ERR_OK;

  error:
    if (NULL != xpath) {
        free(xpath);
    }
    return -1;
}

static int
wireless_xpath_to_interface(sr_session_ctx_t *session, char *xpath, struct wireless_interface *interface) {
    char *name_key = NULL, *ssid_key = NULL;
    sr_xpath_ctx_t state = {0,0,0,0};

    name_key = get_key_value(xpath);
    ssid_key = get_key_value_second(xpath);

    char index_xpath[MAX_XPATH];
    sprintf(index_xpath, index_fmt, name_key, ssid_key);

    sr_val_t *value = NULL;
    int rc = sr_get_item(session, index_xpath, &value);
    if (rc) {
        goto error;
    }

    interface->index = value->data.int32_val;

    interface->option = sr_xpath_last_node(xpath, &state);
    sr_xpath_recover(&state);

    return SR_ERR_OK;

  error:
   return -1;
}

static int
sysrepo_to_uci(sr_session_ctx_t  *session, struct uci_context *uctx, sr_val_t *new_val)
{
    char ucipath[MAX_UCI_PATH];
    char *mem = NULL;
    int rc = SR_ERR_OK;

    if (false == val_has_data(new_val->type)) {
        return SR_ERR_OK;
    }

    if (strstr(new_val->xpath, "interface")) {
        /* handle interface  */
        struct wireless_interface interface = { 0, };
        rc = wireless_xpath_to_interface(session, new_val->xpath, &interface);
        if (rc < 0) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        snprintf(ucipath, MAX_XPATH, "wireless.@wifi-iface[%d].%s", interface.index, interface.option);
        mem = sr_val_to_str(new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "get_uci_item %s", sr_strerror(rc));
        if(mem) free(mem);

        goto exit;
    }

    if (strstr(new_val->xpath, "device")) {
        /* handle device  */
        /* key = get_key_value(new_val->xpath) */;
        struct wireless_device dev = { 0, 0, };
        rc = wireless_xpath_to_device(new_val->xpath, &dev);
        if (rc < 0) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        snprintf(ucipath, MAX_XPATH, "wireless.%s.%s", dev.name, dev.option);
        mem = sr_val_to_str(new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "get_uci_item %s", sr_strerror(rc));
        if(mem) free(mem);

        goto exit;
    }

  exit:
    return SR_ERR_OK;
  error:
    return rc;
  uci_error:
    return SR_ERR_INTERNAL;
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
            rc = sysrepo_to_uci(session, pctx->uctx, new_value);
            sr_print_val(new_value);
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
      }
    }

    INF_MSG("Debug sysrepo values printout:");
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
    int interface_index = 0;

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        /* INF("uci name type %s %s", name, type); */

        if (strcmp("wifi-device", type) == 0) {
            for (size_t i = 0; i < ARR_SIZE(table_wireless); i++) {
                char *uci_val = calloc(1, 100);

                if (strstr(table_wireless[i].ucipath, "@wifi-iface")) {
                    continue;
                }

                snprintf(xpath, MAX_XPATH, table_wireless[i].xpath, name);
                snprintf(ucipath, MAX_UCI_PATH, table_wireless[i].ucipath, name);
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    continue;
                }
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                /* INF("Setting device %s to %s", xpath, uci_val); */
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
                free(uci_val);

                char *ssid = calloc(1,100);

                for (size_t j = 0; j < ARR_SIZE(table_wireless); j++) {
                    char *uci_val = calloc(1, 100);

                    /* INF("[%s][%d] Setting interface %s %s", name, interface_index, */
                    /*     table_wireless[j].ucipath, table_wireless[j].xpath) */
                    if (!strstr(table_wireless[j].ucipath, "@wifi-iface")) {
                        continue;
                    }

                    snprintf(ucipath, MAX_UCI_PATH, table_wireless[j].ucipath, interface_index);
                    rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                    if (UCI_ERR_NOTFOUND == rc) {
                        continue;
                    }
                    if (strstr(ucipath, "ssid") != NULL) {
                        ssid = strdup(uci_val);
                        strcpy(ssid, uci_val);
                        continue;

                    }
                    /* INF("\titem found %s with ssid %s", uci_val, ssid); */

                    if (NULL == ssid) {
                        continue;
                    }
                    snprintf(xpath, MAX_XPATH, table_wireless[j].xpath, name, ssid);
                    /* INF("Setting interface %s to %s", xpath, uci_val); */
                    rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                    SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);

                    snprintf(xpath, MAX_XPATH, index_fmt, name, ssid);
                    sr_val_t *value = NULL;
                    sr_new_val(xpath, &value);
                    value->type = SR_INT32_T;
                    value->data.int32_val = interface_index;
                    rc = sr_set_item(session, xpath, value, SR_EDIT_DEFAULT);
                    SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);

                    free(uci_val);
                }


                free(ssid);
            }
            interface_index = interface_index + 1;
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
