#include "sysrepo.h"
#include "sysrepo/values.h"

typedef int (*adiag_func)(sr_val_t *);

typedef struct adiag_node_func_mapping {
    char *node;
    adiag_func op_func;
} adiag_node_func_m;

/* Operation functions Declaration */
int adiag_version(sr_val_t *);
int adiag_cpu_usage(sr_val_t *);
int adiag_free_memory(sr_val_t *);

int diag_firmware_version(sr_val_t *);
