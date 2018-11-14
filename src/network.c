#include <sr_uci.h>

#include "network.h"
#include "terastream.h"

#define MAX_UBUS_PATH 100
#define UBUS_INVOKE_TIMEOUT 2000

struct status_container {
    const char *ubus_method;
    sfp_ubus_val_to_sr_val transform;
    struct list_head *list;
};

struct ubus_context *ctx;
struct status_container *container_msg;

static char *remove_unit(const char *str)
{
    char *number = (char *) str;
    int i;

    for (i = 0; i < strlen(str); i++) {
        if (number[i] == ' ') {
            number[i] = '\0';
            break;
        }
    }

    return number;
}

static char *transform_state(const char *name)
{
    if (0 == strcmp(name, "INCOMPLETE")) {
        return "incomplete";
    } else if (0 == strcmp(name, "REACHABLE")) {
        return "reachable";
    } else if (0 == strcmp(name, "STALE")) {
        return "stale";
    } else if (0 == strcmp(name, "DELAY")) {
        return "delay";
    } else if (0 == strcmp(name, "PROBE")) {
        return "probe";
    } else {
        return "";
    }
}

bool is_l3_member(json_object *i, json_object *d, char *interface, char *device)
{
    struct json_object *res = NULL, *r;
    const char *l3_device = NULL;

    json_object_object_get_ex(i, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *tmp;
        item = json_object_array_get_idx(r, j);
        json_object_object_get_ex(item, "interface", &tmp);
        if (NULL == tmp)
            continue;
        const char *j_name = json_object_get_string(tmp);
        if (0 == strcmp(j_name, interface) && strlen(interface) == strlen(j_name)) {
            json_object_object_get_ex(item, "l3_device", &tmp);
            if (!tmp)
                continue;
            l3_device = json_object_get_string(tmp);
            if (0 == strcmp(l3_device, device) && strlen(l3_device) == strlen(device)) {
                return true;
            }
        }
    }

    return false;
}

struct json_object *get_device_interface(json_object *i, json_object *d, char *name)
{
    struct json_object *res = NULL, *r;
    const char *l3_device = NULL;

    json_object_object_get_ex(i, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *tmp;
        item = json_object_array_get_idx(r, j);
        json_object_object_get_ex(item, "interface", &tmp);
        if (NULL == tmp)
            continue;
        const char *j_name = json_object_get_string(tmp);
        if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
            json_object_object_get_ex(item, "l3_device", &tmp);
            if (!tmp)
                continue;
            l3_device = json_object_get_string(tmp);
            break;
        }
    }

    json_object_object_foreach(d, key, val)
    {
        if (l3_device && 0 == strcmp(key, l3_device) && strlen(key) == strlen(l3_device)) {
            res = val;
            break;
        }
    }

    return res;
}

struct json_object *get_json_interface(json_object *obj, char *name)
{
    struct json_object *res = NULL, *r;

    json_object_object_get_ex(obj, "interface", &r);
    if (NULL == r)
        return res;

    int j;
    const int N = json_object_array_length(r);
    for (j = 0; j < N; j++) {
        json_object *item, *n;
        item = json_object_array_get_idx(r, j);
        json_object_object_get_ex(item, "interface", &n);
        if (NULL == n)
            continue;
        const char *j_name = json_object_get_string(n);
        if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
            res = item;
            break;
        }
    }

    return res;
}

int network_operational_start()
{
    if (ctx)
        return SR_ERR_OK;
    INF("Connect ubus context. %zu", (size_t) ctx);
    container_msg = calloc(1, sizeof(*container_msg));

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        INF_MSG("Cant allocate ubus\n");
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

void network_operational_stop()
{
    INF_MSG("Free ubus context.");
    INF("%lu %lu", (long unsigned) ctx, (long unsigned) container_msg);
    if (ctx)
        ubus_free(ctx);
    if (container_msg)
        free(container_msg);
}

static void make_status_container(struct status_container **context,
                                  const char *ubus_method_to_call,
                                  sfp_ubus_val_to_sr_val result_function,
                                  struct list_head *list)
{
    *context = container_msg;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
    (*context)->list = list;
}

static void ubus_base_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *json_string;
    struct json_object *base_object;

    struct status_container *status_container_msg;

    status_container_msg = (struct status_container *) req->priv;

    if (!msg) {
        return;
    }

    json_string = blobmsg_format_json(msg, true);
    base_object = json_tokener_parse(json_string);

    status_container_msg->transform(base_object, status_container_msg->list);

    json_object_put(base_object);
    free(json_string);
}

static int ubus_base(const char *ubus_lookup_path, struct status_container *msg, struct blob_buf *blob)
{
    /* INF("list null %d", msg->list==NULL); */
    uint32_t id = 0;
    int u_rc = UBUS_STATUS_OK;
    int rc = SR_ERR_OK;

    u_rc = ubus_lookup_id(ctx, ubus_lookup_path, &id);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no object %s", u_rc, ubus_lookup_path);

    u_rc = ubus_invoke(ctx, id, msg->ubus_method, blob->head, ubus_base_cb, (void *) msg, UBUS_INVOKE_TIMEOUT);
    UBUS_CHECK_RET(u_rc, &rc, cleanup, "ubus [%d]: no method %s", u_rc, msg->ubus_method);

cleanup:
    blob_buf_free(blob);

    return rc;
}

static int network_operational_operstatus(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;

    struct json_object *obj = get_json_interface(u_data->i, interface_name);
    if (!obj)
        return rc;

    json_object_object_get_ex(obj, "up", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_str_data(list_value->value, SR_ENUM_T, !strcmp(ubus_result, "true") ? "up" : "down");

    char xpath[MAX_XPATH];
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/oper-status";
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);

    list_add(&list_value->head, list);

    return rc;
}

static int network_operational_mac(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/phys-address";
    char xpath[MAX_XPATH];

    t = get_device_interface(u_data->i, u_data->d, interface_name);
    if (!t)
        return rc;

    json_object_object_get_ex(t, "macaddr", &t);
    if (!t)
        return rc;
    ubus_result = json_object_get_string(t);

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);

    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, ubus_result);

    list_add(&list_value->head, list);

    return rc;
}

static int network_operational_rx(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    i = get_device_interface(u_data->i, u_data->d, interface_name);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "statistics", &i);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "rx_bytes", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-octets");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "rx_dropped", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-discards");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "rx_errors", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-errors");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "multicast", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-multicast-pkts");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    return rc;
}

static int network_operational_tx(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    i = get_device_interface(u_data->i, u_data->d, interface_name);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "statistics", &i);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "tx_bytes", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-octets");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "tx_dropped", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-discards");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "tx_errors", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-errors");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    return rc;
}

static int network_operational_mtu(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/mtu";
    const char *fmt6 = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/mtu";
    char xpath[MAX_XPATH];

    i = get_device_interface(u_data->i, u_data->d, interface_name);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "mtu", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT16_T;
    // fix 65536 > (2 ^ 16 - 1)
    if (0 == strcmp("65536", ubus_result)) {
        list_value->value->data.uint16_val =  65535;
    } else {
        sscanf(ubus_result, "%hu", &list_value->value->data.uint16_val);
    }
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "ipv6", &t);
    ubus_result = json_object_get_string(t);
    if (ubus_result && 0 == strncmp(ubus_result, "true", strlen(ubus_result))) {
        json_object_object_get_ex(i, "mtu6", &t);
        ubus_result = json_object_get_string(t);
        if (!ubus_result)
            return rc;
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sprintf(xpath, fmt6, interface_name);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT32_T;
        sscanf(ubus_result, "%" PRIu32, &list_value->value->data.uint32_val);
        list_add(&list_value->head, list);
    }

    return rc;
}

static int network_operational_ip(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    const char *ip;
    uint8_t prefix_length = 0;
    struct json_object *ip_obj;
    struct value_node *list_value;
    char xpath[MAX_XPATH];

    struct json_object *obj = get_json_interface(u_data->i, interface_name);
    if (!obj) {
        return rc;
    }

    json_object_object_get_ex(obj, "ipv4-address", &ip_obj);
    if (!ip_obj)
        return rc;

    int j;
    const int N = json_object_array_length(ip_obj);
    for (j = 0; j < N; j++) {
        struct json_object *t = json_object_array_get_idx(ip_obj, j);
        if (!t)
            continue;

        /* Get ip and mask (prefix length) from address. */
        struct json_object *a, *m;
        json_object_object_get_ex(t, "address", &a);
        if (!a)
            continue;
        ip = json_object_get_string(a);

        json_object_object_get_ex(t, "mask", &m);
        if (!a)
            continue;
        prefix_length = (uint8_t) json_object_get_int(m);

        const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length";
        sprintf(xpath, fmt, interface_name, ip);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT8_T;
        list_value->value->data.uint8_val = prefix_length;
        list_add(&list_value->head, list);
    }

    json_object_object_get_ex(obj, "ipv6-address", &ip_obj);
    if (!ip_obj)
        return rc;

    const int N6 = json_object_array_length(ip_obj);
    for (j = 0; j < N6; j++) {
        struct json_object *t = json_object_array_get_idx(ip_obj, j);
        if (!t)
            continue;

        /* Get ip and mask (prefix length) from address. */
        struct json_object *a, *m;
        json_object_object_get_ex(t, "address", &a);
        if (!a)
            continue;
        ip = json_object_get_string(a);

        json_object_object_get_ex(t, "mask", &m);
        if (!a)
            continue;
        prefix_length = (uint8_t) json_object_get_int(m);

        const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/address[ip='%s']/prefix-length";
        sprintf(xpath, fmt, interface_name, ip);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_UINT8_T;
        list_value->value->data.uint8_val = prefix_length;
        list_add(&list_value->head, list);
    }

    return rc;
}

static int network_operational_neigh6(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv6/neighbor[ip='%s']/%s";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(u_data->n, "neighbors", &table);
    if (!table)
        return rc;

    /* Get ip and mask (prefix length) from address. */
    const int N = json_object_array_length(table);
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj, *device_obj, *router_obj, *status_obj;
        const char *ip, *mac, *device, *status;
        bool router;

        iter_object = json_object_array_get_idx(table, i);
        if (!iter_object)
            continue;

        json_object_object_get_ex(iter_object, "device", &device_obj);
        device = json_object_get_string(device_obj);
        if (!device)
            continue;
        if (!is_l3_member(u_data->i, u_data->d, interface_name, (char *) device))
            continue;

        json_object_object_get_ex(iter_object, "ip6addr", &ip_obj);
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);
        json_object_object_get_ex(iter_object, "router", &router_obj);
        json_object_object_get_ex(iter_object, "ip6status", &status_obj);
        ip = json_object_get_string(ip_obj);
        mac = json_object_get_string(mac_obj);
        router = json_object_get_boolean(router_obj);
        status = json_object_get_string(status_obj);
        if (!ip || !mac || !status)
            continue;

        sprintf(xpath, fmt, interface_name, ip, "link-layer-address");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_STRING_T, mac);
        list_add(&list_value->head, list);

        sprintf(xpath, fmt, interface_name, ip, "state");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_ENUM_T, transform_state(status));
        list_add(&list_value->head, list);

        if (!router)
            continue;
        sprintf(xpath, fmt, interface_name, ip, "is-router");
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        list_value->value->type = SR_LEAF_EMPTY_T;
        list_add(&list_value->head, list);
    }

    return rc;
}

static int network_operational_neigh(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/neighbor[ip='%s']/link-layer-address";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(u_data->a, "table", &table);
    if (!table)
        return rc;

    /* Get ip and mask (prefix length) from address. */
    const int N = json_object_array_length(table);
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj, *device_obj;
        const char *ip, *mac, *device;

        iter_object = json_object_array_get_idx(table, i);
        if (!iter_object)
            continue;

        json_object_object_get_ex(iter_object, "device", &device_obj);
        device = json_object_get_string(device_obj);
        if (!device)
            continue;
        if (!is_l3_member(u_data->i, u_data->d, interface_name, (char *) device))
            continue;

        json_object_object_get_ex(iter_object, "ipaddr", &ip_obj);
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);
        ip = json_object_get_string(ip_obj);
        mac = json_object_get_string(mac_obj);
        if (!ip || !mac)
            continue;

        sprintf(xpath, fmt, interface_name, ip);
        printf("XPATH %s\n", xpath);
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_STRING_T, mac);
        list_add(&list_value->head, list);
    }

    return rc;
}

int operstatus_transform(ubus_data * u_data, char *interface_name, struct list_head *list) {
    int rc = SR_ERR_OK;

    rc = network_operational_operstatus(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_mac(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_rx(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_tx(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_mtu(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_ip(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_neigh(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    rc = network_operational_neigh6(u_data, interface_name, list);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

cleanup:
    return rc;
}

static void sfp_rx_pwr_cb(struct json_object *obj, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:rx-pwr";

    json_object_object_get_ex(obj, "rx-pwr", &t);
    if (!t) {
        return;
    }
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_xpath(list_value->value, fmt);

    char *end = NULL;
    double res = strtod(remove_unit(ubus_result), &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

static void sfp_tx_pwr_cb(struct json_object *obj, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:tx-pwr";

    json_object_object_get_ex(obj, "tx-pwr", &t);
    if (!t) {
        return;
    }
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_xpath(list_value->value, fmt);

    char *end = NULL;
    double res = strtod(remove_unit(ubus_result), &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

static void sfp_current_cb(struct json_object *obj, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:current";

    json_object_object_get_ex(obj, "current", &t);
    if (!t) {
        return;
    }

    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_xpath(list_value->value, fmt);

    char *end = NULL;
    double res = strtod(remove_unit(ubus_result), &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

static void sfp_voltage_cb(struct json_object *obj, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/terastream-interfaces-opto:voltage";

    json_object_object_get_ex(obj, "voltage", &t);
    if (!t) {
        return;
    }

    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_xpath(list_value->value, fmt);

    char *end = NULL;
    double res = strtod(remove_unit(ubus_result), &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

int sfp_state_data(struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct status_container *msg = NULL;
    struct blob_buf buf = {0};

    make_status_container(&msg, "get-rx-pwr", sfp_rx_pwr_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-tx-pwr", sfp_tx_pwr_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-current", sfp_current_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

    blob_buf_init(&buf, 0);
    make_status_container(&msg, "get-voltage", sfp_voltage_cb, list);
    rc = ubus_base("sfp.ddm", msg, &buf);
    CHECK_RET(rc, cleanup, "Failed to get ubus state data: %s", sr_strerror(rc));

cleanup:
    return rc;
}

int phy_interfaces_state_cb(ubus_data * u_data, char *interface_name, struct list_head *list)
{
    int rc = SR_ERR_OK;
    struct json_object *t, *i;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/";
    char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

    json_object_object_foreach(u_data->d, key, val)
    {
        if (0 == strcmp(key, interface_name) && strlen(key) == strlen(interface_name)) {
            i = val;
            break;
        }
    }

    /* add type */
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "type");
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_IDENTITYREF_T, "iana-if-type:ethernetCsmacd");
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "macaddr", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) {
        return rc;
    }
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "phys-address");
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, ubus_result);
    list_add(&list_value->head, list);

    if (0 != strcmp(interface_name, "wl0") && 0 != strcmp(interface_name, "wl1")) {
        json_object_object_get_ex(i, "carrier", &t);
        ubus_result = json_object_get_string(t);
        if (!ubus_result) {
            return rc;
        }
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        snprintf(xpath, MAX_XPATH, "%s%s", base, "oper-status");
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_ENUM_T, !strcmp(ubus_result, "true") ? "up" : "down");
        list_add(&list_value->head, list);
    }

    /* get statistics data */
    json_object_object_get_ex(i, "statistics", &i);
    if (!i)
        return rc;

    json_object_object_get_ex(i, "rx_bytes", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) {
        return rc;
    }
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-octets");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "rx_dropped", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) {
        return rc;
    }
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-discards");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "rx_errors", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) {
        return rc;
    }
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-errors");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "multicast", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result) {
        return rc;
    }
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/out-multicast-pkts");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "tx_bytes", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-octets");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "tx_dropped", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-discards");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    json_object_object_get_ex(i, "tx_errors", &t);
    ubus_result = json_object_get_string(t);
    if (!ubus_result)
        return rc;
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "statistics/in-errors");
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT32_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);

    return rc;
}
