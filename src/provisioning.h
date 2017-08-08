#include <stdio.h>
#include "common.h"

int
prov_cpe_reboot(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx);

int
prov_cpe_update(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx);

int
prov_factory_reset(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                   sr_val_t **output, size_t *output_cnt, void *private_ctx);

struct rpc_method {
  char *name;
  int (*method)(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx);
};

