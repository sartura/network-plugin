#include <stdio.h> 
#include <unistd.h>
#include <sys/statvfs.h>

#include "adiag_functions.h"

const char *partition_path = "/";

DIAG_RC
adiag_free_memory(sr_val_t *val)
{
    struct statvfs vfs;
    int rc = 0;

    rc = statvfs(partition_path, &vfs);
    if (rc == -1) {
      return DIAG_UNKNOWN;
    }

    val->type = SR_UINT32_T;
    val->data.uint32_val = (uint32_t) ((vfs.f_blocks - vfs.f_bavail) / (double)(vfs.f_blocks) * 100.0);

    return DIAG_OK;
}

DIAG_RC
adiag_cpu_usage(sr_val_t *val)
{
    long double a[4], b[4];
    long double cpu_usage;
    FILE *fp;

    fp = fopen("/proc/stat","r");
    if (!fp) {
        goto error;
    }
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&a[0],&a[1],&a[2],&a[3]);
    fclose(fp);

    sleep(1);                   /* Interval is needed to measure CPU load. */

    fp = fopen("/proc/stat","r");
    if (!fp) {
        goto error;
    }
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&b[0],&b[1],&b[2],&b[3]);
    fclose(fp);

    cpu_usage = ((b[0]+b[1]+b[2]) - (a[0]+a[1]+a[2])) / ((b[0]+b[1]+b[2]+b[3]) - (a[0]+a[1]+a[2]+a[3]));

    val->type = SR_UINT32_T;
    val->data.uint32_val = (uint32_t) (cpu_usage * 100.0);

    return DIAG_OK;

  error:
    return DIAG_FD_ERR;
}
