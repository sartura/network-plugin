#ifndef TERASTREAM_H
#define TERASTREAM_H

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#include "uci.h"

#define MAX_UCI_PATH 64
#define MAX_XPATH 256

#define ARR_SIZE(a) sizeof a / sizeof a[0]

typedef struct stored_ubus_data {
    json_object *i; // ubus call network.interface dump
    json_object *d; // ubus call network.device status
    json_object *a; // ubus call router.net arp
    json_object *n; // ubus call router.net ipv6_neigh
    json_object *tmp;
} ubus_data;

struct plugin_ctx {
    struct uci_context *uctx;
    sr_subscription_ctx_t *subscription;
    sr_conn_ctx_t *startup_connection;
    sr_session_ctx_t *startup_session;
    ubus_data u_data;
};

#endif /* TERASTREAM_H */
