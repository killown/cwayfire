#ifndef WAYFIRE_SOCKET_H
#define WAYFIRE_SOCKET_H

#include <json-c/json.h>
#include <stdbool.h>

typedef struct WayfireSocket WayfireSocket;

WayfireSocket *wayfire_socket_create(const char *socket_name,
                                     bool allow_manual_search, char **error);
void wayfire_socket_destroy(WayfireSocket *sock);
bool wayfire_socket_is_connected(WayfireSocket *sock);
json_object *wayfire_socket_send_json(WayfireSocket *sock, json_object *msg,
                                      char **error);
json_object *wayfire_socket_read_next_event(WayfireSocket *sock, char **error);
json_object *wayfire_socket_list_methods(WayfireSocket *sock, char **error);
json_object *wayfire_socket_list_views(WayfireSocket *sock,
                                       bool filter_mapped_toplevel,
                                       char **error);
json_object *wayfire_socket_get_option_value(WayfireSocket *sock,
                                             const char *option, char **error);
json_object *wayfire_socket_set_focus(WayfireSocket *sock, int view_id,
                                      char **error);
json_object *wayfire_socket_get_focused_view(WayfireSocket *sock, char **error);
json_object *wayfire_socket_get_cursor_position(WayfireSocket *sock,
                                                char **error);

const char *wayfire_socket_get_socket_name(WayfireSocket *sock);

#endif // WAYFIRE_SOCKET_H
