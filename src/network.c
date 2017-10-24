#include "network.h"
#include "terastream.h"

#include "common.h"

#define MAX_UBUS_PATH 100
#define UBUS_INVOKE_TIMEOUT 2000

struct ubus_context *ctx;

static char *
remove_quotes(const char *str)
{
  char *unquoted;
  unquoted = (char *) str;
  unquoted = unquoted + 1;
  unquoted[strlen(unquoted) - 1] = '\0';

  return unquoted;
}

struct json_object *get_device_interface(json_object *i, json_object *d, char *name) {
	struct json_object *res = NULL, *r;
	const char *l3_device = NULL;

	json_object_object_get_ex(i, "interface", &r);
	if (NULL == r) return res;

	int j;
	const int N = json_object_array_length(r);
	for (j = 0; j < N; j++) {
		json_object *item, *tmp;
		item = json_object_array_get_idx(r, j);
		json_object_object_get_ex(item, "interface", &tmp);
		if (NULL == tmp) continue;
		const char *j_name = json_object_get_string(tmp);
		if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
			json_object_object_get_ex(item, "l3_device", &tmp);
			if (!tmp) continue;
			l3_device = json_object_get_string(tmp);
			break;
		}
	}

	json_object_object_foreach(d, key, val) {
		if (0 == strcmp(key, l3_device) && strlen(key) == strlen(l3_device)) {
			res = val;
			break;
		}
	}

	return res;
}
struct json_object *get_json_interface(json_object *obj, char *name) {
	struct json_object *res = NULL, *r;

	json_object_object_get_ex(obj, "interface", &r);
	if (NULL == r) return res;

	int j;
	const int N = json_object_array_length(r);
	for (j = 0; j < N; j++) {
		json_object *item, *n;
		item = json_object_array_get_idx(r, j);
		json_object_object_get_ex(item, "interface", &n);
		if (NULL == n) continue;
		const char *j_name = json_object_get_string(n);
		if (0 == strcmp(j_name, name) && strlen(name) == strlen(j_name)) {
			res = item;
			break;
		}
	}

	return res;
}

static int
execute_base(const char *interface_name, struct list_head *list, ubus_data u_data, ubus_val_to_sr_val function)
{
	INF("execute interface name %s", interface_name);
	function(u_data, (char *) interface_name, list);
	INF_MSG("finished");
	return SR_ERR_OK;
}

static void
operstatus_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	struct json_object *t;
	const char *ubus_result;
	struct value_node *list_value;

	struct json_object *obj = get_json_interface(u_data.i, interface_name);
	if (!obj) return;

	json_object_object_get_ex(obj, "up", &t);
	ubus_result = json_object_get_string(t);
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
network_operational_operstatus(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, operstatus_transform);
	}

	return SR_ERR_OK;
}

	static void
mac_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	struct json_object *t;
	const char *ubus_result;
	struct value_node *list_value;
	char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/phys-address";
	char xpath[MAX_XPATH];

	INF("ubus_result %s", interface_name);
	t = get_device_interface(u_data.i, u_data.d, interface_name);
	if (!t) return;

	json_object_object_get_ex(t, "macaddr", &t);
	if (!t) return;
	ubus_result = json_object_get_string(t);

	INF("ubus_result %s", ubus_result);

	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);

	sprintf(xpath, fmt, interface_name);
	sr_val_set_xpath(list_value->value, xpath);
	sr_val_set_str_data(list_value->value, SR_STRING_T, remove_quotes(ubus_result));

	list_add(&list_value->head, list);
}

	int
network_operational_mac(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, mac_transform);
	}

	return SR_ERR_OK;
}

static void
rx_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	struct json_object *t, *i;
	const char *ubus_result;
	struct value_node *list_value;
	char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
	char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

	i = get_device_interface(u_data.i, u_data.d, interface_name);
	if (!i) return;

	json_object_object_get_ex(i, "statistics", &i);
	if (!i) return;

	json_object_object_get_ex(i, "rx_bytes", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-octets");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);

	json_object_object_get_ex(i, "rx_dropped", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-discards");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);

	json_object_object_get_ex(i, "rx_errors", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-errors");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);

	json_object_object_get_ex(i, "multicast", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "out-multicast-pkts");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);
}

int
network_operational_rx(char *interface_name, struct list_head *list, ubus_data u_data)
{
	/* Sets the value in ubus callback. */
	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, rx_transform);
	}

	return SR_ERR_OK;
}

static void
tx_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	struct json_object *t, *i;
	const char *ubus_result;
	struct value_node *list_value;
	char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/statistics/";
	char xpath[MAX_XPATH], base[MAX_XPATH];

    snprintf(base, MAX_XPATH, fmt, interface_name);

	i = get_device_interface(u_data.i, u_data.d, interface_name);
	if (!i) return;

	json_object_object_get_ex(i, "statistics", &i);
	if (!i) return;

	json_object_object_get_ex(i, "tx_bytes", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-octets");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);

	json_object_object_get_ex(i, "tx_dropped", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-discards");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);

	json_object_object_get_ex(i, "tx_errors", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;
	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
    snprintf(xpath, MAX_XPATH, "%s%s", base, "in-errors");
	sr_val_set_xpath(list_value->value, xpath);
	list_value->value->type = SR_UINT64_T;
	sscanf(ubus_result, "%" PRIu64, &list_value->value->data.uint64_val);
	list_add(&list_value->head, list);
}

int
network_operational_tx(char *interface_name, struct list_head *list, ubus_data u_data)
{
	/* Sets the value in ubus callback. */

	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, tx_transform);
	}

	return SR_ERR_OK;
}

static void
mtu_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	struct json_object *t;
	const char *ubus_result;
	struct value_node *list_value;
	const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/mtu";
	char xpath[MAX_XPATH];

	json_object_object_get_ex(u_data.i,
			"eth0.1",
			&t);
	if (!t) {
		return;
	}
	ubus_result = json_object_to_json_string(t);

	json_object_object_get_ex(t, "mtu", &t);
	ubus_result = json_object_get_string(t);
	if (!ubus_result) return;

	list_value = calloc(1, sizeof *list_value);
	sr_new_values(1, &list_value->value);
	sprintf(xpath, fmt, interface_name);
	sr_val_set_xpath(list_value->value, xpath);

	list_value->value->type = SR_UINT16_T;
	sscanf(ubus_result, "%hu", &list_value->value->data.uint16_val);

	list_add(&list_value->head, list);

}

	int
network_operational_mtu(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, mtu_transform);
	}

	return SR_ERR_OK;
}

	static void
ip_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
	const char *ip;
	uint8_t prefix_length = 0;
	struct json_object *t;
	struct value_node *list_value;
	char xpath[MAX_XPATH];

	struct json_object *obj = get_json_interface(u_data.i, interface_name);
	if (!obj) {
		return;
	}

    json_object_object_get_ex(obj, "ipv4-address", &t);
    if (!t) {
        return;
    }
    /* ubus_result = json_object_get_string(t); */
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
network_operational_ip(char *interface_name, struct list_head *list, ubus_data u_data)
{
    /* Sets the value in ubus callback. */

	if (NULL != u_data.d) {
		return execute_base(interface_name, list, u_data, ip_transform);
	}

    return SR_ERR_OK;
}


static void
neigh_transform(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
    struct json_object *table, *iter_object;
    /* const char *ubus_result; */
    const char *fmt =
        "/ietf-interfaces:interfaces-state/interface[name='%s']/ietf-ip:ipv4/neighbor[ip='%s']/link-layer-address";
    char xpath[MAX_XPATH];

    json_object_object_get_ex(u_data.i, "table", &table);

    /* Get ip and mask (prefix length) from address. */
    const int N =  	json_object_array_length(table);
    struct value_node *list_value;
    for (int i = 0; i < N; i++) {
        json_object *ip_obj, *mac_obj;
        const char *ip, *mac;

        iter_object = json_object_array_get_idx(table, i);

        json_object_object_get_ex(iter_object, "ipaddr", &ip_obj);
        json_object_object_get_ex(iter_object, "macaddr", &mac_obj);

        ip = json_object_get_string(ip_obj);
        mac = json_object_get_string(mac_obj);

        sprintf(xpath, fmt, interface_name, remove_quotes(ip));
        list_value = calloc(1, sizeof *list_value);
        sr_new_values(1, &list_value->value);
        sr_val_set_xpath(list_value->value, xpath);
        sr_val_set_str_data(list_value->value, SR_STRING_T, remove_quotes(mac));

        list_add(&list_value->head, list);

    }
}

int
network_operational_neigh(char *interface_name, struct list_head *list, ubus_data u_data)
{
    /* Sets the value in ubus callback. */
	if (NULL != u_data.d) {
		//TODO
		//return execute_base(interface_name, list, obj, neigh_transform);
	}

    return SR_ERR_OK;
}

static void
sfp_rx_pwr_cb(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='sfp']/ietf-sfp:ddm/rx-pwr";
    /* char xpath[MAX_XPATH]; */
    char *end = NULL;

    json_object_object_get_ex(u_data.i,
                              "rx-pwr",
                              &t);
    if (!t) {
        return;
    }
    ubus_result = json_object_get_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    /* sprintf(xpath, fmt, interface_name); */
    sr_val_set_xpath(list_value->value, fmt);

    INF("%s", ubus_result);
    int len = strlen(remove_quotes(ubus_result));
    char *decresult = (char*)remove_quotes(ubus_result);
    decresult[len-2] = '\0';
    INF("%s", decresult);

    double res = strtod(decresult, &end);
    INF("%f", res);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

int sfp_rx_pwr(char *interface_name, struct list_head *list, ubus_data u_data) {

	if (NULL != u_data.d) {
		//return execute_base(interface_name, list, obj, sfp_rx_pwr_cb);
	}

    return SR_ERR_OK;
}

static void
sfp_tx_pwr_cb(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='sfp']/ietf-sfp:ddm/tx-pwr";
    /* char xpath[MAX_XPATH]; */
    char *end = NULL;

    json_object_object_get_ex(u_data.i,
                              "tx-pwr",
                              &t);
    if (!t) {
        return;
    }
    ubus_result = json_object_get_string(t);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    /* sprintf(xpath, fmt, interface_name); */
    sr_val_set_xpath(list_value->value, fmt);

    int len = strlen(remove_quotes(ubus_result));
    char *decresult = (char*)remove_quotes(ubus_result);
    decresult[len-2] = '\0';

    double res = strtod(decresult, &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;

    list_add(&list_value->head, list);
}

int sfp_tx_pwr(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		//return execute_base(interface_name, list, obj, sfp_tx_pwr_cb);
	}

    return SR_ERR_OK;
}



static void
sfp_current_cb(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='sfp']/ietf-sfp:ddm/current";
    /* char xpath[MAX_XPATH]; */
    char *end = NULL;

    json_object_object_get_ex(u_data.i,
                              "current",
                              &t);
    if (!t) {
        return;
    }

    ubus_result = json_object_get_string(t);
    INF("%s", ubus_result);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    /* sprintf(xpath, fmt, interface_name); */
    sr_val_set_xpath(list_value->value, fmt);

    INF("%s", remove_quotes(ubus_result));
    int len = strlen(remove_quotes(ubus_result));
    char *decresult = (char*)remove_quotes(ubus_result);
    decresult[len-2] = '\0';
    INF("%s", decresult);

    list_value->value->type = SR_DECIMAL64_T;
    double res = strtod(decresult, &end);
    INF("%f", res);
    list_value->value->data.decimal64_val = res;
    sr_print_val(list_value->value);
    INF_MSG("");

    list_add(&list_value->head, list);
}


int sfp_current(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		//return execute_base(interface_name, list, obj, sfp_current_cb);
	}

    return SR_ERR_OK;
}

static void
sfp_voltage_cb(ubus_data u_data, char *interface_name, struct list_head *list)
{
	INF_MSG("function call");
    struct json_object *t;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = "/ietf-interfaces:interfaces-state/interface[name='sfp']/ietf-sfp:ddm/voltage";
    /* char xpath[MAX_XPATH]; */
    char *end = NULL;

    json_object_object_get_ex(u_data.i,
                              "voltage",
                              &t);
    if (!t) {
        return;
    }

    ubus_result = json_object_get_string(t);
    INF("%s", ubus_result);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    /* sprintf(xpath, fmt, interface_name) */;
    sr_val_set_xpath(list_value->value, fmt);

    int len = strlen(remove_quotes(ubus_result));
    char *decresult = (char*)remove_quotes(ubus_result);
    decresult[len-2] = '\0';
    INF("%s", decresult);
    double res = strtod(decresult, &end);
    list_value->value->type = SR_DECIMAL64_T;
    list_value->value->data.decimal64_val = res;
    sr_print_val(list_value->value);
    INF("%f", res);

    list_add(&list_value->head, list);
}

int sfp_voltage(char *interface_name, struct list_head *list, ubus_data u_data)
{
	if (NULL != u_data.d) {
		//return execute_base(interface_name, list, obj, sfp_voltage_cb);
	}

    return SR_ERR_OK;

}
