#include <unistd.h>

#include "provisioning.h"

void
prov_reboot_cpe()
{
  execl("/sbin/reboot", "reboot", (char *) NULL);
}

PROV_SC
prov_factory_reset()
{
  /* Check if firmware was installed from SquashFS image? */

  /* Run firstboot. */
  execl("/sbin/firstboot", "firstboot", (char *) NULL);

  /* Reboot the computer. */
  prov_reboot_cpe();
}

PROV_SC
prov_firmware_upgrade(char *image_url, char *image_md5)
{
  /* Download image. */

  /* Check integrity. */
  
  /* Execute system upgrade. */

  return PROV_OK;
}
