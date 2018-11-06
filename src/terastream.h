#ifndef TERASTREAM_H
#define TERASTREAM_H

#include <sr_uci.h>

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

#endif /* TERASTREAM_H */
