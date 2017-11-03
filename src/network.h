#ifndef NETWORK_H
#define NETWORK_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#include "terastream.h"

#define MAX_XPATH 256

struct value_node {
    struct list_head head;
    sr_val_t *value;
};

typedef void (*ubus_val_to_sr_val)(ubus_data, char *, struct list_head *list);
typedef void (*sfp_ubus_val_to_sr_val)(struct json_object *, struct list_head *list);

typedef int (*oper_func)(char *, struct list_head *, ubus_data);
typedef int (*sfp_oper_func)(struct list_head *);

typedef struct oper_mapping {
    char *node;
    oper_func op_func;
} oper_mapping;

typedef struct sfp_oper_mapping {
    char *node;
    sfp_oper_func op_func;
} sfp_oper_mapping;

int network_operational_start();
void network_operational_stop();

int network_operational_operstatus(char *, struct list_head *, ubus_data);
int network_operational_mac(char *, struct list_head *, ubus_data);
int network_operational_rx(char *, struct list_head *, ubus_data);
int network_operational_tx(char *, struct list_head *, ubus_data);
int network_operational_mtu(char *, struct list_head *, ubus_data);
int network_operational_ip(char *, struct list_head *, ubus_data);
int network_operational_neigh(char *, struct list_head *, ubus_data);
int network_operational_neigh6(char *, struct list_head *, ubus_data);

int sfp_rx_pwr(struct list_head *);
int sfp_tx_pwr(struct list_head *);
int sfp_current(struct list_head *);
int sfp_voltage(struct list_head *);

#endif /* NETWORK_H */
