#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>


typedef void (*ubus_val_to_sr_val)(json_object *, sr_val_t *);

int network_operational_operstatus(sr_val_t *);
int network_operational_mac(sr_val_t *);
int network_operational_rx(sr_val_t *);
int network_operational_tx(sr_val_t *);
int network_operational_mtu(sr_val_t *);
int network_operational_ip(sr_val_t *);
int network_operational_neigh(sr_val_t *val);
