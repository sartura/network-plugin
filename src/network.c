#include "network.h"

#include "common.h"

struct status_container {
    sr_val_t *value;
    const char *ubus_method;
    ubus_val_to_sr_val transform;
};

static void
make_status_container(struct status_container **context,
                      const char *ubus_method_to_call,
                      ubus_val_to_sr_val result_function,
                      sr_val_t *value)
{
    *context = calloc(1, sizeof *context);
    (*context)->value = value;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
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

    json_string = blobmsg_format_json(msg, true);
    base_object = json_tokener_parse(json_string);
    /* INF("\n---JSON_STRING = %s \n---", json_string); */

    /* TODO */
    status_container_msg->transform(base_object, status_container_msg->value);
    /* end TODO */

    json_object_put(base_object);
    free(json_string);
    free(status_container_msg);
    INF_MSG("\n---END= \n---");
}

static int
ubus_base(const char *ubus_lookup_path,
            struct status_container *msg)
{
    uint32_t id = 0;
    struct blob_buf buf = {0,};
    int rc = SR_ERR_OK;


    struct ubus_context *ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Cant allocate ubus\n");
        goto exit;
    }

    blob_buf_init(&buf, 0);

    rc = ubus_lookup_id(ctx, ubus_lookup_path, &id);

    if (rc) {
        INF("ubus [%d]: no object %s\n", rc, ubus_lookup_path);
        goto exit;
    }
    rc = ubus_invoke(ctx, id, msg->ubus_method, buf.head, ubus_base_cb, (void *) msg, 1000);
    if (rc) {
        INF("ubus [%d]: no object %s\n", rc, msg->ubus_method);
        goto exit;
    }

  exit:
    blob_buf_free(&buf);

    return rc;

}

static void
operstatus_transform(json_object *base, sr_val_t *value)
{
    struct json_object *t;
    const char *ubus_result;
    json_object_object_get_ex(base,
                              "up",
                              &t);
    ubus_result = json_object_to_json_string(t);

    sr_val_set_str_data(value, SR_ENUM_T,
                        !strcmp(ubus_result, "true") ? "up" : "down");
}

int
network_operational_operstatus(sr_val_t *val)
{
    /* Sets the value in ubus callback. */
    sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/oper-status");
    /* sr_val_set_str_data(&val[0], SR_ENUM_T, "up"); */
    sr_print_val(&val[0]);

    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_transform, val);
    ubus_base("network.interface.wan", msg);

    return SR_ERR_OK;
}

static char *
remove_quotes(const char *str)
{
    char *unquoted;
    unquoted = strdup(str);
    unquoted = unquoted + 1;
    unquoted[strlen(unquoted) - 1] = '\0';

    return strdup(unquoted);
}

static void
mac_transform(json_object *base, sr_val_t *value)
{
    struct json_object *t;
    const char *ubus_result;
    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    /* INF("%s", ubus_result); */

    json_object_object_get_ex(t, "macaddr", &t);
    ubus_result = json_object_to_json_string(t);
    INF("%s", ubus_result);

    sr_val_set_str_data(value, SR_STRING_T, remove_quotes(ubus_result));
}

int
network_operational_mac(sr_val_t *val)
{
    /* Sets the value in ubus callback. */
    sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/phys-address");

    struct status_container *msg;
    msg = calloc(1, sizeof *msg);
    msg->value = val;
    msg->transform = mac_transform;
    msg->ubus_method = "status";


    ubus_base("network.device", msg);

    return SR_ERR_OK;
}

static void
rx_transform(json_object *base, sr_val_t *value)
{
    struct json_object *t;
    const char *ubus_result;
    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    /* INF("%s", ubus_result); */

    json_object_object_get_ex(t, "statistics", &t);
    ubus_result = json_object_to_json_string(t);
    json_object_object_get_ex(t, "rx_bytes", &t);
    ubus_result = json_object_to_json_string(t);

    value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64, &value->data.uint64_val);
    sr_val_set_str_data(value, SR_UINT64_T, ubus_result);
}

int
network_operational_rx(sr_val_t *val)
{
    /* Sets the value in ubus callback. */
    sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/statistics/out-octets");

    struct status_container *msg = NULL;
    make_status_container(&msg, "status", rx_transform, val);
    ubus_base("network.device", msg);

    return SR_ERR_OK;
}

static void
tx_transform(json_object *base, sr_val_t *value)
{
    struct json_object *t;
    const char *ubus_result;
    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    /* INF("%s", ubus_result); */

    json_object_object_get_ex(t, "statistics", &t);
    ubus_result = json_object_to_json_string(t);
    json_object_object_get_ex(t, "tx_bytes", &t);
    ubus_result = json_object_to_json_string(t);

    value->type = SR_UINT64_T;
    sscanf(ubus_result, "%" PRIu64 , &value->data.uint64_val);
    sr_val_set_str_data(value, SR_UINT64_T, ubus_result);
}

int
network_operational_tx(sr_val_t *val)
{
    /* Sets the value in ubus callback. */
    sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/statistics/in-octets");

    struct status_container *msg;
    make_status_container(&msg, "status", tx_transform, val);
    ubus_base("network.device", msg);

    return SR_ERR_OK;
}

static void
mtu_transform(json_object *base, sr_val_t *value)
{
    struct json_object *t;
    const char *ubus_result;
    json_object_object_get_ex(base,
                              "br-lan",
                              &t);
    ubus_result = json_object_to_json_string(t);
    /* INF("%s", ubus_result); */

    json_object_object_get_ex(t, "mtu", &t);
    ubus_result = json_object_to_json_string(t);

    value->type = SR_UINT16_T;
    sscanf(ubus_result, "%hu", &value->data.uint16_val);
    INF("%s %hu", ubus_result, value->data.uint16_val);
    sr_val_set_str_data(value, SR_UINT16_T, ubus_result);
}

int
network_operational_mtu(sr_val_t *val)
{
    /* Sets the value in ubus callback. */
    sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/ietf-ip:ipv4/mtu");

    struct status_container *msg;
    make_status_container(&msg, "status", mtu_transform, val);
    ubus_base("network.device", msg);

    return SR_ERR_OK;
}

static void
ip_transform(json_object *base, sr_val_t *value)
{
    const char *ip;
    uint8_t prefix_length = 0;
    struct json_object *t;
    const char *ubus_result;

    json_object_object_get_ex(base, "ipv4-address", &t);
    ubus_result = json_object_to_json_string(t);
    INF("%s", ubus_result);

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

    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='wan']/ietf-ip:ipv4/address[ip='%s']/prefix-length";
    char xpath[100];
    sprintf(xpath, fmt, ip);
    sr_val_set_xpath(value, xpath);
    value->type = SR_UINT8_T;
    value->data.uint8_val = prefix_length;
}

int
network_operational_ip(sr_val_t *val)
{
    /* Sets the value in ubus callback. */

    struct status_container *msg;
    make_status_container(&msg, "status", ip_transform, val);
    ubus_base("network.interface.wan", msg);

    return SR_ERR_OK;
}


/* static void */
/* neigh_transform(json_object *base, sr_val_t *value) */
/* { */
/*     struct json_object *table, *iter_object; */
/*     const char *ubus_result; */
/*     char xpath[100]; */
/*     const char *fmt = */
/*         "/ietf-interfaces:interfaces-state/interface[name='wan']/ietf-ip:ipv4/address[ip='%s']/neighbor[ip='%s]/link-layer-address"; */
/*     INF("%s", json_object_to_json_string(base)); */

/*     json_object_object_get_ex(base, "table", &table); */
/*     ubus_result = json_object_to_json_string(table); */
/*     INF("---TABLE:\n%s", ubus_result); */

/*     /\* Get ip and mask (prefix length) from address. *\/ */
/*     enum json_type type; */
/*     const int N =  	json_object_array_length(table); */
/*     INF("table has %d entries.", N); */
/*     for (int i = 0; i < N; i++) { */
/*         json_object *ip_obj, *mac_obj; */
/*         const char *ip, *mac; */

/*         iter_object = json_object_array_get_idx(table, i); */
/*         INF("[%d]\n\t%s", i, json_object_to_json_string(iter_object)); */

/*         json_object_object_get_ex(iter_object, "ipaddr", &ip_obj); */
/*         json_object_object_get_ex(iter_object, "macaddr", &mac_obj); */

/*         ip = json_object_to_json_string(ip_obj); */
/*         mac = json_object_to_json_string(mac_obj); */
/*         INF("\t\t%s", ip); */
/*         INF("\t\t%s", mac); */

/*         sprintf(xpath, fmt, ip); */
/*         sr_val_set_xpath(&value[i], xpath); */
/*         (&value[i])->type = SR_STRING_T; */
/*         (&value[i])->data.string_val = strdup(mac); */
/*     } */
/* } */

/* int */
/* network_operational_neigh(sr_val_t *val) */
/* { */
/*     /\* Sets the value in ubus callback. *\/ */

/*     struct status_container *msg; */
/*     msg = calloc(1, sizeof *msg); */
/*     msg->value = val; */
/*     msg->transform = neigh_transform; */
/*     msg->ubus_method = "arp"; */


/*     ubus_base("router.net", msg); */

/*     return SR_ERR_OK; */
/* } */
