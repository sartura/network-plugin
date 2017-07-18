#include <stdio.h>

typedef enum {
  PROV_OK,
  PROV_FAIL,
} PROV_SC;

void
prov_reboot_cpe();

PROV_SC
prov_factory_reset();

PROV_SC
prov_firmware_upgrade();
