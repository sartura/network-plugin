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

typedef void (*ubus_val_to_sr_val)(ubus_data *, char *, struct list_head *list);
typedef void (*sfp_ubus_val_to_sr_val)(struct json_object *, struct list_head *list);

int network_operational_start();
void network_operational_stop();

int operstatus_transform(ubus_data *, char *, struct list_head *);

int sfp_state_data(struct list_head *);

int phy_interfaces_state_cb(ubus_data *, char *, struct list_head *);

#endif /* NETWORK_H */
