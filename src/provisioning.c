#include <unistd.h>

#include "provisioning.h"

int
prov_cpe_reboot(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    execl("/sbin/reboot", "reboot", (char *) NULL);

    return 0;
}

int
prov_cpe_update(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    /* TODO */
    /* Download image. */

    /* Check integrity. */

    /* Execute system upgrade. */
    return -1;
}

int
prov_factory_reset(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                   sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    /* Check if firmware was installed from SquashFS image? */

    /* Run firstboot. */
    execl("/sbin/firstboot", "firstboot", (char *) NULL);

    /* Reboot the computer. */
    execl("/sbin/reboot", "reboot", (char *) NULL);

    return 0;
}
