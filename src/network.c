#include "network.h"

#include "common.h"

struct status_container {
    char *interface_name;
    const char *ubus_method;
    ubus_val_to_sr_val transform;
    struct list_head *list;
};

struct ubus_context *ctx;
struct status_container *container_msg;

static char *
remove_quotes(const char *str)
{
  char *unquoted;
  unquoted = (char *) str;
  unquoted = unquoted + 1;
  unquoted[strlen(unquoted) - 1] = '\0';

  return unquoted;
}
int
network_operational_start()
{
    if (ctx) return 0;
    INF("Connect ubus context. %zu", (size_t) ctx);
    container_msg = calloc(1,sizeof(*container_msg));

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        INF_MSG("Cant allocate ubus\n");
        return -1;
    }

    return 0;
}

void
network_operational_stop()
{
    INF_MSG("Free ubus context.");
    INF("%lu %lu", (long unsigned)ctx, (long unsigned) container_msg);
    if (ctx) ubus_free(ctx);
    if (container_msg) free(container_msg);
}

static void
make_status_container(struct status_container **context,
                      const char *ubus_method_to_call,
                      ubus_val_to_sr_val result_function,
                      char *interface_name, struct list_head *list)
{
    *context = container_msg;
    (*context)->interface_name = interface_name;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
    (*context)->list = list;
}

static void
ubus_base_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *json_string;
    struct json_object *base_object;

    struct status_container *status_container_msg;

    status_container_msg = (struct status_container *) req->priv;

    if (!msg) {
        return;
    }
    /* INF("list null %d", status_container_msg->list==NULL); */

    json_string = blobmsg_format_json(msg, true);
    base_object = json_tokener_parse(json_string);
    /* INF("\n---JSON_STRING = %s \n---", json_string); */

    /* TODO */
    status_container_msg->transform(base_object, status_container_msg->interface_name, status_container_msg->list);
    /* end TODO */

    json_object_put(base_object);
    free(json_string);
}

static int
ubus_base(const char *ubus_lookup_path,
          struct status_container *msg,
          struct blob_buf *blob)
{
    /* INF("list null %d", msg->list==NULL); */
    uint32_t id = 0;
    int rc = SR_ERR_OK;

    char ubuf[100];
    sprintf(ubuf, ubus_lookup_path, msg->interface_name);
    /* INF("ctx null %d %s\n\t%s", ctx==NULL, ubus_lookup_path, ubuf); */
    rc = ubus_lookup_id(ctx, ubuf, &id);
    if (rc) {
        INF("ubus [%d]: %s\n", rc, ubus_strerror(rc));
        goto exit;
    }

    rc = ubus_invoke(ctx, id, msg->ubus_method, blob->head, ubus_base_cb, (void *) msg, 2000);
    if (rc) {
        INF("ubus [%s]: no object %s\n", ubus_strerror(rc), msg->ubus_method);
        goto exit;
    }

  exit:
    blob_buf_free(blob);

    return rc;

}

static void
operstatus_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;

    json_object_object_get_ex(base,
                              "up",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_str_data(list_value->value, SR_ENUM_T,
                        !strcmp(ubus_result, "true") ? strdup("up") : strdup("down"));

    char xpath[MAX_XPATH];
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/oper-status";
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);

    list_add(&list_value->head, list);
}

int
network_operational_operstatus(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.interface.%s", msg, &buf);

    return SR_ERR_OK;
}

static void
mac_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/phys-address";
    char xpath[MAX_XPATH];


    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);

    json_object_object_get_ex(t,
                              "macaddr",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, remove_quotes(ubus_result));

    //list_value->value->xpath = strdup("/ietf-interfaces:interfaces-state/interface[name='wan']/phys-address");
    list_add(&list_value->head, list);
}

int
network_operational_mac(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", mac_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.device", msg, &buf);

    return SR_ERR_OK;
}

static void
rx_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/out-octets";
    char xpath[MAX_XPATH];


    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    json_object_object_get_ex(t, "statistics", &t);
    /* ubus_result = json_object_to_json_string(t); */
    json_object_object_get_ex(t, "rx_bytes", &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);

    list_add(&list_value->head, list);
}

int
network_operational_rx(char *interface_name, struct list_head *list)
{
    /* Sets the value in ubus callback. */

    struct status_container *msg = NULL;
    make_status_container(&msg, "status", rx_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.device", msg, &buf);

    return SR_ERR_OK;
}

static void
tx_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/statistics/in-octets";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);

    json_object_object_get_ex(t, "statistics", &t);
    ubus_result = json_object_to_json_string(t);
    json_object_object_get_ex(t, "tx_bytes", &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);

    list_value->value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
    list_add(&list_value->head, list);
}

int
network_operational_tx(char *interface_name, struct list_head *list)
{
    /* Sets the value in ubus callback. */

    struct status_container *msg;
    make_status_container(&msg, "status", tx_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.device", msg, &buf);

    return SR_ERR_OK;
}

static void
mtu_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/mtu";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base,
                              "eth0.1",
                              &t);
    if (!t) {
      return;
    }
     ubus_result = json_object_to_json_string(t);
    /* INF("%s", ubus_result); */

    json_object_object_get_ex(t, "mtu", &t);
    ubus_result = json_object_to_json_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    //    sr_val_set_xpath(list_value->value, "/ietf-interfaces:interfaces-state/interface[name='wan']/ietf-ip:ipv4/mtu");
    sr_val_set_xpath(list_value->value, xpath);

    list_value->value->type = SR_UINT16_T;
    sscanf(ubus_result, "%hu", &list_value->value->data.uint16_val);

    list_add(&list_value->head, list);

}

int
network_operational_mtu(char *interface_name, struct list_head *list)
{
    struct status_container *msg;
    make_status_container(&msg, "status", mtu_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.device", msg, &buf);

    return SR_ERR_OK;
}

static void
ip_transform(json_object *base, char *interface_name, struct list_head *list)
{
    const char *ip;
    uint8_t prefix_length = 0;
    struct json_object *t;
    struct value_node *list_value;
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base, "ipv4-address", &t);
    if (!t) {
        return;
    }
    /* ubus_result = json_object_to_json_string(t); */
    /* INF("%s", ubus_result); */

    t = json_object_array_get_idx(t, 0);
    if (!t) {
        INF_MSG("Missing ip address.");
        return;
    }

    /* Get ip and mask (prefix length) from address. */
    enum json_type type;
    json_object_object_foreach(t, key, val) {
        (void) key;
        type = json_object_get_type(val);
        if (type == json_type_string) {
            ip = json_object_get_string(val);
        } else if (json_type_int) {
            prefix_length = (uint8_t) json_object_get_int(val);
        }
    }

    const char *fmt =
        "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/address[ip='%s']/prefix-length";

    sprintf(xpath, fmt, interface_name, ip);
    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sr_val_set_xpath(list_value->value, xpath);
    list_value->value->type = SR_UINT8_T;
    list_value->value->data.uint8_val = prefix_length;

    list_add(&list_value->head, list);
}

int
network_operational_ip(char *interface_name, struct list_head *list)
{
    /* Sets the value in ubus callback. */

    struct status_container *msg;
    make_status_container(&msg, "status", ip_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("network.interface.%s", msg, &buf);

    return SR_ERR_OK;
}


static void
neigh_transform(json_object *base, char *interface_name, struct list_head *list)
{
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt =
        "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/neighbor[ip='%s']/link-layer-address";
    char xpath[MAX_XPATH];

    /* INF("%s", json_object_to_json_string(base)); */

    json_object_object_get_ex(base, "table", &table);
    /* ubus_result = json_object_to_json_string(table); */
    /* INF("---TABLE:\n%s", ubus_result); */

    /* Get ip and mask (prefix length) from address. */
    // enum json_type type;
    const int N =  	json_object_array_length(table);
    /* INF("table has %d entries.", N); */
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj;
        const char *ip, *mac;

        iter_object = json_object_array_get_idx(table, i);
        /* INF("[%d]\n\t%s", i, json_object_to_json_string(iter_object)); */

        json_object_object_get_ex(iter_object, "ipaddr", &ip_obj);
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);

        ip = json_object_to_json_string(ip_obj);
        mac = json_object_to_json_string(mac_obj);
        /* INF("\t\t%s", ip); */
        /* INF("\t\t%s", mac); */

        sprintf(xpath, fmt, interface_name, remove_quotes(ip));
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, strdup(xpath));
        sr_val_set_str_data(list_value->value, SR_STRING_T, remove_quotes(mac));
        sr_print_val(list_value->value);

        list_add(&list_value->head, list);

    }
}

int
network_operational_neigh(char *interface_name, struct list_head *list)
{
    /* Sets the value in ubus callback. */
    struct status_container *msg;
    make_status_container(&msg, "arp", neigh_transform, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    ubus_base("router.net", msg, &buf);

    return SR_ERR_OK;
}
