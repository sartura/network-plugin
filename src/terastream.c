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
#include "common.h"

const char *YANG_MODEL = "ietf-interfaces";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    char *default_value;
    char ucipath[MAX_UCI_PATH];
    char xpath[MAX_XPATH];
} sr_uci_link;

/* Mappings of uci options to Sysrepo xpaths. */
static sr_uci_link table_sr_uci[] = {
    {"", "network.%s.ipaddr", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/ip"},
    {"", "network.%s.ip6addr", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/ip"},
    {"1500", "network.%s.mtu", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/mtu"},
    {"1500", "network.%s.mtu", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/mtu"},
    {"true", "network.%s.enabled", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/enabled"},
    {"true", "network.%s.enabled", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/enabled"},
    {"24", "network.%s.ip4prefixlen", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length"},
    {"64", "network.%s.ip6prefixlen", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length"},
    {"", "network.%s.netmask", "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/netmask"},
};

static const char *xpath_network_type_format = "/ietf-interfaces:interfaces/interface[name='%s']/type";
static const char *default_interface_type = "iana-if-type:ethernetCsmacd";

static oper_mapping table_interface_status[] = {
    {"oper-status", network_operational_operstatus},
    {"phys-address", network_operational_mac},
    {"out-octets", network_operational_rx},
    {"in-octets", network_operational_tx},
    {"mtu", network_operational_mtu},
    {"ip", network_operational_ip},
    {"neighbor", network_operational_neigh},
    {"neighbor6", network_operational_neigh6},
};

static sfp_oper_mapping table_sfp_status[] = {
    {"rx-pwr", sfp_rx_pwr},
    {"tx-pwr", sfp_tx_pwr},
    {"voltage", sfp_voltage},
    {"current", sfp_current},
};

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(struct plugin_ctx *pctx, sr_val_t *value);

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);

/* get UCI boolean value */
static bool parse_uci_bool(char *value)
{

    if (0 == strncmp("1", value, strlen(value))) {
        return true;
    } else if (0 == strncmp("yes", value, strlen(value))) {
        return true;
    } else if (0 == strncmp("on", value, strlen(value))) {
        return true;
    } else if (0 == strncmp("true", value, strlen(value))) {
        return true;
    } else if (0 == strncmp("enabled", value, strlen(value))) {
        return true;
    } else {
        return true;
    }
};

static bool val_has_data(sr_type_t type)
{
    /* types containing some data */
    if (type == SR_BINARY_T)
        return true;
    else if (type == SR_BITS_T)
        return true;
    else if (type == SR_BOOL_T)
        return true;
    else if (type == SR_DECIMAL64_T)
        return true;
    else if (type == SR_ENUM_T)
        return true;
    else if (type == SR_IDENTITYREF_T)
        return true;
    else if (type == SR_INSTANCEID_T)
        return true;
    else if (type == SR_INT8_T)
        return true;
    else if (type == SR_INT16_T)
        return true;
    else if (type == SR_INT32_T)
        return true;
    else if (type == SR_INT64_T)
        return true;
    else if (type == SR_STRING_T)
        return true;
    else if (type == SR_UINT8_T)
        return true;
    else if (type == SR_UINT16_T)
        return true;
    else if (type == SR_UINT32_T)
        return true;
    else if (type == SR_UINT64_T)
        return true;
    else if (type == SR_ANYXML_T)
        return true;
    else if (type == SR_ANYDATA_T)
        return true;
    else
        return false;
}

static void restart_network_over_ubus(int wait_time)
{
    /*
    struct blob_buf buf = {0};
    uint32_t id = 0;
    int u_rc = 0;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "network", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object network\n", u_rc);
        goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "restart", buf.head, NULL, NULL, wait_time * 1000);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object restart\n", u_rc);
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    */
    system("/etc/init.d/network reload > /dev/null");
}

char *get_key_value(char *orig_xpath, int n)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};
    int counter = 0;

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto error;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            if (counter++ != n)
                continue;
            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    return key;
}

static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
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

static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
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

void ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct plugin_ctx *pctx = req->priv;
    struct json_object *r = NULL;
    char *json_result = NULL;

    if (msg) {
        json_result = blobmsg_format_json(msg, true);
        r = json_tokener_parse(json_result);
    } else {
        goto cleanup;
    }
    pctx->u_data.tmp = r;

cleanup:
    if (NULL != json_result) {
        free(json_result);
    }
    return;
}

static void clear_ubus_data(struct plugin_ctx *pctx)
{
    /* clear data out if it exists */
    if (pctx->u_data.i) {
        json_object_put(pctx->u_data.i);
        pctx->u_data.i = NULL;
    }
    if (pctx->u_data.d) {
        json_object_put(pctx->u_data.d);
        pctx->u_data.d = NULL;
    }
    if (pctx->u_data.a) {
        json_object_put(pctx->u_data.a);
        pctx->u_data.a = NULL;
    }
    if (pctx->u_data.n) {
        json_object_put(pctx->u_data.n);
        pctx->u_data.n = NULL;
    }
}

static int get_oper_interfaces(struct plugin_ctx *pctx)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    int u_rc = UBUS_STATUS_OK;

    clear_ubus_data(pctx);

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "network.device", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object network.device\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "status", buf.head, ubus_cb, pctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object status\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    pctx->u_data.d = pctx->u_data.tmp;
    blob_buf_free(&buf);

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "network.interface", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object network.interaface\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "dump", buf.head, ubus_cb, pctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object dump\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    pctx->u_data.i = pctx->u_data.tmp;
    blob_buf_free(&buf);

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.net", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.net\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "arp", buf.head, ubus_cb, pctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object arp\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    pctx->u_data.a = pctx->u_data.tmp;
    blob_buf_free(&buf);

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.net", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object router.net\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    u_rc = ubus_invoke(u_ctx, id, "ipv6_neigh", buf.head, ubus_cb, pctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object ipv6_neigh\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    pctx->u_data.n = pctx->u_data.tmp;
    blob_buf_free(&buf);

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static int config_xpath_to_ucipath(struct plugin_ctx *pctx, sr_uci_link *mapping, sr_val_t *value)
{
    char *val_str = NULL;
    char ucipath[MAX_UCI_PATH];
    char xpath[MAX_XPATH];
    int rc = SR_ERR_OK;
    char *device_name = get_key_value(value->xpath, 0);
    char *ip = get_key_value(value->xpath, 1);

    if (!device_name)
        goto exit;

    sprintf(xpath, mapping->xpath, device_name, ip);

    val_str = sr_val_to_str(value);
    if (!val_str) {
        ERR("val_to_str %s", sr_strerror(rc));
        rc = SR_ERR_INTERNAL;
        goto exit;
    }

    if (0 != strncmp(value->xpath, xpath, strlen(xpath))) {
        goto exit;
    }
    INF("SET %s -> %s", xpath, val_str);

    sprintf(ucipath, mapping->ucipath, device_name);
    rc = set_uci_item(pctx->uctx, ucipath, val_str);
    UCI_CHECK_RET(rc, exit, "sr_get_item %s", sr_strerror(rc));

exit:
    if (val_str)
        free(val_str);
    if (device_name)
        free(device_name);
    if (ip)
        free(ip);

    return rc;
}

static int config_store_to_uci(struct plugin_ctx *pctx, sr_val_t *value)
{
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    if (false == val_has_data(value->type)) {
        return SR_ERR_OK;
    }

    for (int i = 0; i < n_mappings; i++) {
        if (0 == strcmp(sr_xpath_node_name(value->xpath), sr_xpath_node_name(table_sr_uci[i].xpath))) {
            rc = config_xpath_to_ucipath(pctx, &table_sr_uci[i], value);
            SR_CHECK_RET(rc, error, "Failed to map xpath to ucipath: %s", sr_strerror(rc));
        }
    }

error:
    return rc;
}

static int parse_network_config(struct plugin_ctx *pctx)
{
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    char ucipath[MAX_UCI_PATH] = {0};
    char xpath[MAX_XPATH] = {
        0,
    };
    char *value = calloc(1, MAX_UCI_PATH);
    char *ip = NULL;
    int rc;

    rc = uci_load(pctx->uctx, "network", &package);
    UCI_CHECK_RET(rc, error, "uci_load %s error", "network");

    uci_foreach_element(&package->sections, e)
    {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("interface", type) == 0) {
            bool ipv6 = false;
            bool dhcp = false;
            /* parse the interface, check IP type
             * IPv4 -> static, dhcp; IPv6 -> dhcpv6 */

            INF("processing interface %s", name);
            snprintf(ucipath, MAX_UCI_PATH, "network.%s.proto", name);
            rc = get_uci_item(pctx->uctx, ucipath, &value);
            UCI_CHECK_RET(rc, error, "get_uci_item %s", ucipath);
            if (0 == strncmp("dhcpv6", value, strlen(value)))
                ipv6 = true;
            if (0 == strncmp("dhcp", value, strlen("dhcp")))
                dhcp = true;
            char *interface = ipv6 ? "6" : "4";

            snprintf(ucipath, MAX_UCI_PATH, "network.%s.mtu", name);
            rc = get_uci_item(pctx->uctx, ucipath, &value);
            if (rc != UCI_OK)
                strcpy(value, "1500");
            snprintf(xpath, MAX_XPATH, "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/mtu", name, interface);
            rc = sr_set_item_str(pctx->startup_session, xpath, value, SR_EDIT_DEFAULT);

            snprintf(ucipath, MAX_UCI_PATH, "network.%s.enabled", name);
            rc = get_uci_item(pctx->uctx, ucipath, &value);
            if (rc != UCI_OK)
                parse_uci_bool(value) ? strcpy(value, "true") : strcpy(value, "false");
            snprintf(xpath, MAX_XPATH, "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/enabled", name, interface);
            rc = sr_set_item_str(pctx->startup_session, xpath, value, SR_EDIT_DEFAULT);

            if (!dhcp) {
                snprintf(ucipath, MAX_UCI_PATH, "network.%s.ipaddr", name);
                rc = get_uci_item(pctx->uctx, ucipath, &value);
                UCI_CHECK_RET(rc, error, "get_uci_item %s", ucipath);
                ip = strdup(value);

                /* check if netmask exists, if not use prefix-length */
                snprintf(ucipath, MAX_UCI_PATH, "network.%s.netmask", name);
                rc = get_uci_item(pctx->uctx, ucipath, &value);
                if (rc == UCI_OK) {
                    snprintf(xpath,
                             MAX_XPATH,
                             "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/address[ip='%s']/netmask",
                             name,
                             interface,
                             ip);
                    rc = sr_set_item_str(pctx->startup_session, xpath, value, SR_EDIT_DEFAULT);
                } else {
                    snprintf(ucipath, MAX_UCI_PATH, "network.%s.ip%sprefixlen", interface, name);
                    rc = get_uci_item(pctx->uctx, ucipath, &value);
                    if (rc != UCI_OK)
                        ipv6 ? strcpy(value, "64") : strcpy(value, "24");
                    snprintf(xpath,
                             MAX_XPATH,
                             "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/address[ip='%s']/prefix-length",
                             name,
                             interface,
                             ip);
                    rc = sr_set_item_str(pctx->startup_session, xpath, value, SR_EDIT_DEFAULT);
                }
            }

            sprintf(xpath, xpath_network_type_format, name);
            rc = sr_set_item_str(pctx->startup_session, xpath, default_interface_type, SR_EDIT_DEFAULT);
            SR_CHECK_RET(rc, error, "Couldn't add type for interface %s: %s", xpath, sr_strerror(rc));

            if (ip)
                free(ip);
            ip = NULL;
        }
    }

    INF_MSG("commit the sysrepo changes");
    rc = sr_commit(pctx->startup_session);
    SR_CHECK_RET(rc, error, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

error:
    if (package)
        uci_unload(pctx->uctx, package);
    free(value);
    if (ip)
        free(ip);
    return rc;
}

static void print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
    switch (op) {
        case SR_OP_CREATED:
            if (NULL != new_val) {
                printf("CREATED: ");
                sr_print_val(new_val);
            }
            break;
        case SR_OP_DELETED:
            if (NULL != old_val) {
                printf("DELETED: ");
                sr_print_val(old_val);
            }
            break;
        case SR_OP_MODIFIED:
            if (NULL != old_val && NULL != new_val) {
                printf("MODIFIED: ");
                printf("old value ");
                sr_print_val(old_val);
                printf("new value ");
                sr_print_val(new_val);
            }
            break;
        case SR_OP_MOVED:
            if (NULL != new_val) {
                printf("MOVED: %s after %s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
            }
            break;
    }
}

static int parse_change(sr_session_ctx_t *session, struct plugin_ctx *pctx, const char *module_name, sr_notif_event_t event)
{
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_change_iter_t *it = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char xpath[256] = {
        0,
    };

    snprintf(xpath, 256, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, xpath, &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", xpath);
        goto error;
    }

    while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
        print_change(oper, old_value, new_value);
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = config_store_to_uci(pctx, new_value);
        }
        sr_free_val(old_value);
        sr_free_val(new_value);
        CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
    }

error:
    if (NULL != it) {
        sr_free_change_iter(it);
    }
    return rc;
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int rc = SR_ERR_OK;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    INF("%s configuration has changed.", YANG_MODEL);

    /* copy ietf-sytem running to startup */
    if (SR_EV_APPLY == event) {
        /* copy running datastore to startup */

        rc = sr_copy_config(pctx->startup_session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
        if (SR_ERR_OK != rc) {
            WRN_MSG("Failed to copy running datastore to startup");
            /* TODO handle this error */
            return rc;
        }
        restart_network_over_ubus(2);
        return SR_ERR_OK;
    }

    rc = parse_change(session, pctx, module_name, event);
    CHECK_RET(rc, error, "failed to apply sysrepo: %s", sr_strerror(rc));

error:
    return rc;
}

static size_t list_size(struct list_head *list)
{
    size_t current_size = 0;
    struct value_node *vn;

    list_for_each_entry(vn, list, head)
    {
        current_size += 1;
    }

    return current_size;
}

int sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
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

static int data_provider_interface_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    (void) pctx;
    size_t n_mappings;
    int rc = SR_ERR_OK;
    bool has_wan = false;

    if (strlen(cb_xpath) > strlen("/ietf-interfaces:interfaces-state")) {
        return SR_ERR_OK;
    }

    rc = get_oper_interfaces(pctx);
    SR_CHECK_RET(rc, exit, "Couldn't initialize uci interfaces: %s", sr_strerror(rc));
    /* copy json objects from ubus call network.device status to pctx->data */

    struct list_head list = LIST_HEAD_INIT(list);
    oper_func func;
    n_mappings = ARR_SIZE(table_interface_status);

    for (size_t i = 0; i < n_mappings; i++) {
        func = table_interface_status[i].op_func;

        /* get interface list */
        struct json_object *r = NULL;
        json_object_object_get_ex(pctx->u_data.i, "interface", &r);
        if (NULL == r)
            continue;

        int j;
        const int N = json_object_array_length(r);
        for (j = 0; j < N; j++) {
            json_object *item, *n;
            item = json_object_array_get_idx(r, j);
            json_object_object_get_ex(item, "interface", &n);
            if (NULL == n)
                continue;
            char *interface = json_object_get_string(n);
            if (0 == strncmp(interface, "wan", strlen(interface)))
                has_wan = true;
            rc = func(interface, &list, pctx->u_data);
        }
    }
    // hard code physical interfaces
    rc = phy_interfaces_state("eth1", &list, pctx->u_data);
    rc = phy_interfaces_state("eth2", &list, pctx->u_data);
    rc = phy_interfaces_state("eth3", &list, pctx->u_data);
    rc = phy_interfaces_state("eth4", &list, pctx->u_data);
    rc = phy_interfaces_state("wl0", &list, pctx->u_data);
    rc = phy_interfaces_state("wl1", &list, pctx->u_data);

    if (has_wan) {
        sfp_oper_func sfp_func;
        n_mappings = ARR_SIZE(table_sfp_status);
        for (size_t i = 0; i < n_mappings; i++) {
            sfp_func = table_sfp_status[i].op_func;
            rc = sfp_func(&list);
        }
    }

    size_t cnt = 0;
    cnt = list_size(&list);
    INF("Allocating %zu values.", cnt);

    struct value_node *vn, *q;
    size_t j = 0;
    rc = sr_new_values(cnt, values);
    INF("%s", sr_strerror(rc));

    list_for_each_entry_safe(vn, q, &list, head)
    {
        rc = sr_dup_val_data(&(*values)[j], vn->value);
        SR_CHECK_RET(rc, exit, "Couldn't copy value: %s", sr_strerror(rc));
        j += 1;
        sr_free_val(vn->value);
        list_del(&vn->head);
        free(vn);
    }

    *values_cnt = cnt;

    list_del(&list);

    if (*values_cnt > 0) {
        INF("Debug sysrepo values printout: %zu", *values_cnt);
        for (size_t i = 0; i < *values_cnt; i++) {
            sr_print_val(&(*values)[i]);
        }
    }

exit:
    clear_ubus_data(pctx);
    return rc;
}

static int sync_datastores(struct plugin_ctx *ctx)
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
        INF_MSG("copy uci data to sysrepo");
        rc = parse_network_config(ctx);
        SR_CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        SR_CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc = SR_ERR_OK;
    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-network");

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

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-network");
    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    INF("sr_plugin_init_cb for sysrepo-plugin-dt-network %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to operational data");
    rc = sr_dp_get_items_subscribe(
        session, "/ietf-interfaces:interfaces-state", data_provider_interface_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    rc = network_operational_start();
    SR_CHECK_RET(rc, error, "Could not init ubus: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    if (ctx->subscription) {
        sr_unsubscribe(session, ctx->subscription);
    }
    free(ctx);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx)
        return;

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

static void sigint_handler(__attribute__((unused)) int signum)
{
    INF_MSG("Sigint called, exiting...");
    exit_application = 1;
}

int main()
{
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
        sleep(1); /* or do some more useful work... */
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
