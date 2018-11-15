/**
 * @file terastream.c
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief Sysrepo plugin for ietf-interfaces.
 *
 * @copyright
 * Copyright (C) 2018 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <sr_uci.h>

#include "terastream.h"
#include "network.h"
#include "openwrt.h"
#include "version.h"

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

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(sr_ctx_t *ctx, sr_val_t *value);

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
    system("/etc/init.d/network reload > /dev/null");
}

void ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    sr_ctx_t *ctx = req->priv;
    struct json_object *r = NULL;
    char *json_result = NULL;

    if (msg) {
        json_result = blobmsg_format_json(msg, true);
        r = json_tokener_parse(json_result);
    } else {
        goto cleanup;
    }
    ubus_data *u_data = (ubus_data *) ctx->data;
    u_data->tmp = r;

cleanup:
    if (NULL != json_result) {
        free(json_result);
    }
    return;
}

static void clear_ubus_data(sr_ctx_t *ctx)
{
    ubus_data *u_data = (ubus_data *) ctx->data;
    /* clear data out if it exists */
    if (u_data->i) {
        json_object_put(u_data->i);
        u_data->i = NULL;
    }
    if (u_data->d) {
        json_object_put(u_data->d);
        u_data->d = NULL;
    }
    if (u_data->a) {
        json_object_put(u_data->a);
        u_data->a = NULL;
    }
    if (u_data->n) {
        json_object_put(u_data->n);
        u_data->n = NULL;
    }
}

static int get_oper_interfaces(sr_ctx_t *ctx)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    int u_rc = UBUS_STATUS_OK;
    ubus_data *u_data = (ubus_data *) ctx->data;

    clear_ubus_data(ctx);

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "network.device", &id);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, "network.device");
    u_rc = ubus_invoke(u_ctx, id, "status", buf.head, ubus_cb, ctx, 0);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, "status");
    u_data->d = u_data->tmp;
    blob_buf_free(&buf);

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "network.interface", &id);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, "network.interface");
    u_rc = ubus_invoke(u_ctx, id, "dump", buf.head, ubus_cb, ctx, 0);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, "dump");
    u_data->i = u_data->tmp;
    blob_buf_free(&buf);

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.net", &id);
    if (UBUS_STATUS_NOT_FOUND == u_rc) {
        INF_MSG("using generic functions");
        rc = openwrt_rap(u_data->a);
        CHECK_RET_MSG(rc, cleanup, "failed openwrt_arp()");
    } else {
        UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, "router.net");
        u_rc = ubus_invoke(u_ctx, id, "arp", buf.head, ubus_cb, ctx, 0);
        UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, "arp");
        u_data->a = u_data->tmp;
        blob_buf_free(&buf);
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.net", &id);
    if (UBUS_STATUS_NOT_FOUND == u_rc) {
        INF_MSG("using generic functions");
        rc = openwrt_ipv6_neigh(u_data->n);
        CHECK_RET_MSG(rc, cleanup, "failed openwrt_ipv6_neigh()");
    } else {
        UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, "router.net");
        u_rc = ubus_invoke(u_ctx, id, "ipv6_neigh", buf.head, ubus_cb, ctx, 0);
        UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, "ipv6_neigh");
        u_data->n = u_data->tmp;
        blob_buf_free(&buf);
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

static int config_xpath_to_ucipath(sr_ctx_t *ctx, sr_uci_link *mapping, sr_val_t *value)
{
    char *val_str = NULL;
    char ucipath[MAX_UCI_PATH];
    char xpath[MAX_XPATH];
    int uci_rc, rc = SR_ERR_OK;
    char *device_name = get_n_key_value(value->xpath, 0);
    char *ip = get_n_key_value(value->xpath, 1);

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
    uci_rc = set_uci_item(ctx->uctx, ucipath, val_str);
    UCI_CHECK_RET(uci_rc, &rc, exit, "get_uci_item %d %s", uci_rc, ucipath);

exit:
    if (val_str)
        free(val_str);
    if (device_name)
        free(device_name);
    if (ip)
        free(ip);

    return rc;
}

static int config_store_to_uci(sr_ctx_t *ctx, sr_val_t *value)
{
    const int n_mappings = ARR_SIZE(table_sr_uci);
    int rc = SR_ERR_OK;

    if (false == val_has_data(value->type)) {
        return SR_ERR_OK;
    }

    for (int i = 0; i < n_mappings; i++) {
        if (0 == strcmp(sr_xpath_node_name(value->xpath), sr_xpath_node_name(table_sr_uci[i].xpath))) {
            rc = config_xpath_to_ucipath(ctx, &table_sr_uci[i], value);
            CHECK_RET(rc, error, "Failed to map xpath to ucipath: %s", sr_strerror(rc));
        }
    }

error:
    return rc;
}

static int parse_network_config(sr_ctx_t *ctx)
{
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    char ucipath[MAX_UCI_PATH] = {0};
    char xpath[MAX_XPATH] = {
        0,
    };
    char *value = calloc(1, MAX_UCI_PATH);
    int rc, uci_rc;

    uci_rc = uci_load(ctx->uctx, "network", &package);
    UCI_CHECK_RET(uci_rc, &rc, error, "uci_load %d %s", uci_rc, "network");

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
            uci_rc = get_uci_item(ctx->uctx, ucipath, &value);
            UCI_CHECK_RET(uci_rc, &rc, error, "get_uci_item %d %s", uci_rc, ucipath);
            if (0 == strncmp("dhcpv6", value, strlen(value)))
                ipv6 = true;
            if (0 == strncmp("dhcp", value, strlen("dhcp")))
                dhcp = true;
            char *interface = ipv6 ? "6" : "4";

            snprintf(ucipath, MAX_UCI_PATH, "network.%s.mtu", name);
            rc = get_uci_item(ctx->uctx, ucipath, &value);
            if (rc != UCI_OK)
                strcpy(value, "1500");
            snprintf(xpath, MAX_XPATH, "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/mtu", name, interface);
            rc = sr_set_item_str(ctx->startup_sess, xpath, value, SR_EDIT_DEFAULT);

            snprintf(ucipath, MAX_UCI_PATH, "network.%s.enabled", name);
            rc = get_uci_item(ctx->uctx, ucipath, &value);
            if (rc != UCI_OK)
                parse_uci_bool(value) ? strcpy(value, "true") : strcpy(value, "false");
            snprintf(xpath, MAX_XPATH, "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/enabled", name, interface);
            rc = sr_set_item_str(ctx->startup_sess, xpath, value, SR_EDIT_DEFAULT);

            if (!dhcp) {
                snprintf(ucipath, MAX_UCI_PATH, "network.%s.ipaddr", name);
                uci_rc = get_uci_item(ctx->uctx, ucipath, &value);
                UCI_CHECK_RET(uci_rc, &rc, error, "get_uci_item %d %s", uci_rc, ucipath);

                /* check if netmask exists, if not use prefix-length */
                snprintf(ucipath, MAX_UCI_PATH, "network.%s.netmask", name);
                rc = get_uci_item(ctx->uctx, ucipath, &value);
                if (rc == UCI_OK) {
                    snprintf(xpath,
                             MAX_XPATH,
                             "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/address[ip='%s']/netmask",
                             name,
                             interface,
                             value);
                    rc = sr_set_item_str(ctx->startup_sess, xpath, value, SR_EDIT_DEFAULT);
                } else {
                    snprintf(ucipath, MAX_UCI_PATH, "network.%s.ip%sprefixlen", interface, name);
                    rc = get_uci_item(ctx->uctx, ucipath, &value);
                    if (rc != UCI_OK)
                        ipv6 ? strcpy(value, "64") : strcpy(value, "24");
                    snprintf(xpath,
                             MAX_XPATH,
                             "/ietf-interfaces:interfaces/interface[name='%s']/ietf-ip:ipv%s/address[ip='%s']/prefix-length",
                             name,
                             interface,
                             value);
                    rc = sr_set_item_str(ctx->startup_sess, xpath, value, SR_EDIT_DEFAULT);
                }
            }

            sprintf(xpath, xpath_network_type_format, name);
            rc = sr_set_item_str(ctx->startup_sess, xpath, default_interface_type, SR_EDIT_DEFAULT);
            CHECK_RET(rc, error, "Couldn't add type for interface %s: %s", xpath, sr_strerror(rc));
        }
    }

    INF_MSG("commit the sysrepo changes");
    rc = sr_commit(ctx->startup_sess);
    CHECK_RET(rc, error, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

error:
    if (package)
        uci_unload(ctx->uctx, package);
    free(value);
    return rc;
}

static int parse_change(sr_session_ctx_t *session, sr_ctx_t *ctx, const char *module_name, sr_notif_event_t event)
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
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = config_store_to_uci(ctx, new_value);
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
    sr_ctx_t *ctx = (sr_ctx_t *) private_ctx;
    INF("%s configuration has changed.", YANG_MODEL);

    /* copy ietf-sytem running to startup */
    if (SR_EV_APPLY == event) {
        /* copy running datastore to startup */

        rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
        if (SR_ERR_OK != rc) {
            WRN_MSG("Failed to copy running datastore to startup");
            /* TODO handle this error */
            return rc;
        }
        restart_network_over_ubus(2);
        return SR_ERR_OK;
    }

    rc = parse_change(session, ctx, module_name, event);
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

static int
#ifdef SYSREPO_LESS_0_7_5
data_provider_interface_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
#else
data_provider_interface_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, void *private_ctx)
#endif
{
    sr_ctx_t *ctx = (sr_ctx_t *) private_ctx;
    (void) ctx;
    int rc = SR_ERR_OK;
    bool has_wan = false;
    ubus_data *u_data = (ubus_data *) ctx->data;

    if (strlen(cb_xpath) > strlen("/ietf-interfaces:interfaces-state")) {
        return SR_ERR_OK;
    }

    rc = get_oper_interfaces(ctx);
    CHECK_RET(rc, exit, "Couldn't initialize uci interfaces: %s", sr_strerror(rc));
    /* copy json objects from ubus call network.device status to ctx->data */

    struct list_head list = LIST_HEAD_INIT(list);

    /* get interface list */
    struct json_object *r = NULL;
    json_object_object_get_ex(u_data->i, "interface", &r);
    if (NULL != r) {
        int j;
        const int N = json_object_array_length(r);
        for (j = 0; j < N; j++) {
            json_object *item, *n;
            item = json_object_array_get_idx(r, j);
            json_object_object_get_ex(item, "interface", &n);
            if (NULL == n)
                continue;
            char *interface = (char *) json_object_get_string(n);
            if (0 == strncmp(interface, "wan", strlen(interface)))
                has_wan = true;
            rc = operstatus_transform(u_data, interface, &list);
            INF("operstatus_transform %s", sr_strerror(rc));
        }
    }
    // get list of bridge members and call phy_interfaces_state_cb
    json_object_object_foreach(u_data->d, key, val)
    {
        // suppress unused warning
        (void) (key);
        json_object_object_get_ex(val, "bridge-members", &r);
        if (NULL != r) {
            int j = 0;
            const int N = json_object_array_length(r);
            for (j = 0; j < N; j++) {
                json_object *item;
                item = json_object_array_get_idx(r, j);
                rc = phy_interfaces_state_cb(u_data, (char *) json_object_get_string(item), &list);
                INF("phy_interfaces_state_cb %s", sr_strerror(rc));
            }
        }
    }

    // get sfp state date
    if (has_wan) {
        rc = sfp_state_data(&list);
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
        CHECK_RET(rc, exit, "Couldn't copy value: %s", sr_strerror(rc));
        j += 1;
        sr_free_val(vn->value);
        list_del(&vn->head);
        free(vn);
    }

    *values_cnt = cnt;

    list_del(&list);

    //if (*values_cnt > 0) {
    //    INF("Debug sysrepo values printout: %zu", *values_cnt);
    //    for (size_t i = 0; i < *values_cnt; i++) {
    //        sr_print_val(&(*values)[i]);
    //    }
    //}

exit:
    clear_ubus_data(ctx);
    return rc;
}

static int sync_datastores2(sr_ctx_t *ctx)
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
        CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc = SR_ERR_OK;
    sr_ctx_t *ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_MSG(ctx, &rc, error, "failed to calloc sr_ctx_t");
    ctx->data = NULL;
    ctx->uctx = NULL;

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-network");

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    CHECK_NULL_MSG(ctx->uctx, &rc, error, "failed to uci_alloc_context()");

    ctx->data = calloc(1, sizeof(ubus_data));
    CHECK_NULL_MSG(ctx->data, &rc, error, "failed to calloc ubus_data");

    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->startup_conn);
    CHECK_RET(rc, error, "Error by sr_connect: %s", sr_strerror(rc));

    rc = sr_session_start(ctx->startup_conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->startup_sess);
    CHECK_RET(rc, error, "Error by sr_session_start: %s", sr_strerror(rc));

    *private_ctx = ctx;

    /* Init type for interface... */
    rc = sync_datastores2(ctx);
    CHECK_RET(rc, error, "Couldn't initialize datastores: %s", sr_strerror(rc));

    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-dt-network");
    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->sub);
    CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    INF("sr_plugin_init_cb for sysrepo-plugin-dt-network %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to operational data");
    rc = sr_dp_get_items_subscribe(
        session, "/ietf-interfaces:interfaces-state", data_provider_interface_cb, *private_ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
    CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    rc = network_operational_start();
    CHECK_RET(rc, error, "Could not init ubus: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx)
        return;

    sr_ctx_t *ctx = private_ctx;
    if (NULL != ctx->sub) {
        sr_unsubscribe(session, ctx->sub);
    }
    if (NULL != ctx->startup_sess) {
        sr_session_stop(ctx->startup_sess);
    }
    if (NULL != ctx->startup_conn) {
        sr_disconnect(ctx->startup_conn);
    }
    if (NULL != ctx->uctx) {
        uci_free_context(ctx->uctx);
    }
    network_operational_stop();
    if (NULL != ctx->data) {
        free(ctx->data);
    }
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
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    INF_MSG("Initializing plugin ...");
    rc = sr_plugin_init_cb(session, &private_ctx);
    CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1); /* or do some more useful work... */
    }

cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
}
#endif
