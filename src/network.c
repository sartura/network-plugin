#include <network.h>

#include "common.h"

static void
oper_status_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
  char *json_string;
  const char *status;
  struct json_object *r, *t;

  struct status_container {
      sr_val_t *value;
      char *status_parameter;
  } *status_container_msg;

  status_container_msg = (struct status_container *) req->priv;

  sr_val_t *val = (sr_val_t *) status_container_msg->value;

  fprintf(stderr, "systemboard cb\n");
  if (!msg) {
      return;
  }

  json_string = blobmsg_format_json(msg, true);
  r = json_tokener_parse(json_string);
  INF("\n---JSON_STRING = %s \n---", json_string);

  /* UP */
  json_object_object_get_ex(r, "up", &t);
  status = json_object_to_json_string(t);
  INF("\n---UP = %s \n---", status);
  sr_val_set_str_data(val, SR_ENUM_T, strdup(status));

  json_object_object_get_ex(r, "dns-server", &t);
  status = json_object_to_json_string(t);
  INF("\n---DNS = %s \n---", status);


  INF("%s", status_container_msg->value->xpath);
  /* sr_val_set_str_data(val, SR_STRING_T, strdup(status)); */
  sr_val_set_str_data(val, SR_ENUM_T, "up");

  INF_MSG("\n---END= \n---");
  json_object_put(r);
  free(json_string);
  INF_MSG("\n---ENDEND= \n---");
}

static int
oper_status(const char *ubus_path, sr_val_t *val)
{
  uint32_t id = 0;
  struct blob_buf buf = {0,};
  int rc = SR_ERR_OK;

  struct status_container {
      sr_val_t *value;
      char *status_parameter;
  } *status_container_msg;
  status_container_msg = calloc(1, sizeof *status_container_msg);

  struct ubus_context *ctx = ubus_connect(NULL);
  if (ctx == NULL) {
      fprintf(stderr, "Cant allocate ubus\n");
      goto exit;
  }

  blob_buf_init(&buf, 0);

  rc = ubus_lookup_id(ctx, ubus_path, &id);

  if (rc) {
      fprintf(stderr, "ubus [%d]: no object network.interface.wan\n", rc);
      goto exit;
  }
  status_container_msg->status_parameter = "up";
  status_container_msg->value = val;
  INF("%s", status_container_msg->value->xpath);
  rc = ubus_invoke(ctx, id, "status", buf.head, oper_status_cb, (void *) status_container_msg, 1000);
  if (rc) {
      fprintf(stderr, "ubus [%d]: no object status\n", rc);
      goto exit;
  }

exit:
  blob_buf_free(&buf);

  return rc;

}

void
network_get_operstatus(sr_val_t *val)
{
  /* Sets the value in ubus callback. */
  sr_val_set_xpath(&val[0], "/ietf-interfaces:interfaces-state/interface[name='wan']/oper-status");
  /* sr_val_set_str_data(&val[0], SR_ENUM_T, "up"); */
  sr_print_val(&val[0]);

  oper_status("network.interface.wan", val);
}

