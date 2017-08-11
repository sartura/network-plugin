#include <stdio.h> 
#include <unistd.h>
#include <sys/statvfs.h>

#include "adiag_functions.h"
#include "common.h"

const char *partition_path = "/";

int
adiag_version(sr_val_t *val)
{
    FILE *fp;
    char buff[100];

    fp = fopen("/etc/openwrt_version","r");
    if (!fp) {
        goto error;
    }
    fscanf(fp,"%s", buff);
    fclose(fp);

    sr_val_set_xpath(val, "/provisioning:hgw-diagnostics/version");
    sr_val_set_str_data(val, SR_STRING_T, buff);

    return SR_ERR_OK;

  error:
    return -1;
}

int
adiag_free_memory(sr_val_t *val)
{
    struct statvfs vfs;
    int rc = 0;

    INF_MSG("1.");
    rc = statvfs(partition_path, &vfs);
    if (rc == -1) {
      return SR_ERR_INTERNAL;
    }
    INF_MSG("2.");

    rc = sr_val_set_xpath(val, "/provisioning:hgw-diagnostics/memory-status");
    val->type = SR_UINT32_T;
    val->data.uint32_val = (uint32_t) ((vfs.f_blocks - vfs.f_bavail) / (double)(vfs.f_blocks) * 100.0);
    /* val->data.uint32_val = 42; */
    printf("adiag_free_memory %d\n", val->data.uint32_val);
    INF_MSG("3.");

    return SR_ERR_OK;
}

int
adiag_cpu_usage(sr_val_t *val)
{
    long double a[4], b[4];
    long double cpu_usage;
    FILE *fp;
    int rc = SR_ERR_OK;

    fp = fopen("/proc/stat","r");
    if (!fp) {
        rc = SR_ERR_IO;
        goto error;
    }
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&a[0],&a[1],&a[2],&a[3]);
    fclose(fp);

    sleep(1);                   /* Interval is needed to measure CPU load. */

    fp = fopen("/proc/stat","r");
    if (!fp) {
        rc = SR_ERR_IO;
        goto error;
    }
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&b[0],&b[1],&b[2],&b[3]);
    fclose(fp);

    cpu_usage = ((b[0]+b[1]+b[2]) - (a[0]+a[1]+a[2])) / ((b[0]+b[1]+b[2]+b[3]) - (a[0]+a[1]+a[2]+a[3]));

    rc = sr_val_set_xpath(val, "/provisioning:hgw-diagnostics/cpu-usage");
    val->type = SR_UINT32_T;
    val->data.uint32_val = (uint32_t) (cpu_usage * 100.0);

    printf("calculated cpu-usage %d %Lf\n", val->data.uint32_val, cpu_usage);

    return SR_ERR_OK;

  error:
    return rc;
}
