#include "sysrepo.h"

/* Model */
typedef enum {
    DIAG_OK = 0,
    DIAG_FD_ERR,
    DIAG_UNKNOWN
} DIAG_RC;

typedef DIAG_RC (*adiag_func)(sr_val_t *);

typedef struct adiag_node_func_mapping {
    char *node;
    adiag_func op_func;
} adiag_node_func_m;

/* Operation functions Declaration */
DIAG_RC adiag_version(sr_val_t *);
DIAG_RC adiag_cpu_usage(sr_val_t *);
DIAG_RC adiag_free_memory(sr_val_t *);

DIAG_RC diag_firmware_version(sr_val_t *);
