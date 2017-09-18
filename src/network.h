#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#define MAX_XPATH 256

struct value_node {
  struct list_head head;
  sr_val_t *value;
};

typedef void (*ubus_val_to_sr_val)(json_object *, sr_val_t *, struct list_head *list);

typedef int (*oper_func)(sr_val_t *, struct list_head *);


typedef struct oper_mapping {
  char *node;
  oper_func op_func;
} oper_mapping;


int network_operational_start();
void network_operational_stop();

int network_operational_operstatus(sr_val_t *, struct list_head *);
int network_operational_mac(sr_val_t *, struct list_head *);
int network_operational_rx(sr_val_t *, struct list_head *);
int network_operational_tx(sr_val_t *, struct list_head *);
int network_operational_mtu(sr_val_t *, struct list_head *);
int network_operational_ip(sr_val_t *, struct list_head *);
int network_operational_neigh(sr_val_t *val, struct list_head *);
