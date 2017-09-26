#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#include "uci.h"

#define MAX_UCI_PATH 64
#define MAX_XPATH 256
#define MAX_INTERFACES 10
#define MAX_INTERFACE_NAME 20

#define ARR_SIZE(a) sizeof a / sizeof a[0]


struct plugin_ctx {
  struct uci_context *uctx;
  sr_subscription_ctx_t *subscription;
  sr_conn_ctx_t *startup_connection;
  sr_session_ctx_t *startup_session;
  size_t interface_count;
  char interface_names[MAX_INTERFACES][MAX_INTERFACE_NAME];
};
