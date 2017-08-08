#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"
#include "sysrepo/plugins.h"

#include "uci.h"

#define MAX_UCI_PATH 64
#define MAX_XPATH 64

#define ARR_SIZE(a) sizeof a / sizeof a[0]


struct plugin_ctx {
  struct uci_context *uctx;
  sr_subscription_ctx_t *subscription;
};

/* Update UCI configuration from Sysrepo datastore. */
static int config_store_to_uci(struct plugin_ctx *pctx, sr_session_ctx_t *sess);

/* Update startup datastore configuration from UCI configuration file values. */
static int config_uci_to_store(struct plugin_ctx *pctx, sr_session_ctx_t *sess);

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);
