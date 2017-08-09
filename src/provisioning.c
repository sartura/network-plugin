#include <unistd.h>

#include "provisioning.h"

int
prov_cpe_reboot(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
  printf("Resetting this thingy...\n");
  int N = 4;
  for (int i = 0 ; i < N; i++) {
    printf("%d\n", i);
    sleep(1);
  }
  (void) output;
  (void) output_cnt;
    execl("/sbin/reset", "reset", (char *) NULL);

    return 0;
}

int
prov_cpe_update(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    /* TODO */
    /* Download image. */

    /* Check integrity. */

  (void) output;
  (void) output_cnt;

   /* Execute system upgrade. */
    return -1;
}

int
prov_factory_reset(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                   sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
  (void) output;
  (void) output_cnt;
    /* Check if firmware was installed from SquashFS image? */

    /* Run firstboot. */
    execl("/sbin/firstboot", "firstboot", (char *) NULL);

    /* Reboot the computer. */
    execl("/sbin/reboot", "reboot", (char *) NULL);


    return 0;
}
