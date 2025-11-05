#define _GNU_SOURCE

#include "wayfire_socket.h"
#include <dirent.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct WfPathNode {
  char *path;
  struct WfPathNode *next;
} WfPathNode;

typedef struct WfEventNode {
  json_object *event;
  struct WfEventNode *next;
} WfEventNode;

struct WayfireSocket {
  int fd;
  char *socket_name;
  WfEventNode *pending_events_head;
  WfEventNode *pending_events_tail;
};

static void set_error(char **error, const char *message) {
  if (error && *error == NULL) {
    *error = strdup(message);
  }
}

static void path_list_add(WfPathNode **head, const char *path) {
  WfPathNode *new_node = (WfPathNode *)malloc(sizeof(WfPathNode));
  new_node->path = strdup(path);
  new_node->next = *head;
  *head = new_node;
}

static void path_list_free(WfPathNode *head) {
  while (head) {
    WfPathNode *temp = head;
    head = head->next;
    free(temp->path);
    free(temp);
  }
}

static void event_list_queue(WayfireSocket *sock, json_object *event) {
  WfEventNode *new_node = (WfEventNode *)malloc(sizeof(WfEventNode));
  new_node->event = event;
  new_node->next = NULL;
  if (sock->pending_events_tail) {
    sock->pending_events_tail->next = new_node;
  }
  sock->pending_events_tail = new_node;
  if (!sock->pending_events_head) {
    sock->pending_events_head = new_node;
  }
}

static json_object *event_list_dequeue(WayfireSocket *sock) {
  if (!sock->pending_events_head) {
    return NULL;
  }
  WfEventNode *temp = sock->pending_events_head;
  json_object *event = temp->event;
  sock->pending_events_head = temp->next;
  if (!sock->pending_events_head) {
    sock->pending_events_tail = NULL;
  }
  free(temp);
  return event;
}

static bool _read_exact(int fd, void *buf, size_t n, char **error) {
  char *p = (char *)buf;
  size_t remaining = n;
  while (remaining > 0) {
    ssize_t n_read = read(fd, p, remaining);
    if (n_read <= 0) {
      set_error(error, "Failed to read from socket, connection closed.");
      return false;
    }
    p += n_read;
    remaining -= n_read;
  }
  return true;
}

static bool _write_exact(int fd, const void *buf, size_t n, char **error) {
  const char *p = (const char *)buf;
  size_t remaining = n;
  while (remaining > 0) {
    ssize_t n_written = write(fd, p, remaining);
    if (n_written <= 0) {
      set_error(error, "Failed to write to socket, connection closed.");
      return false;
    }
    p += n_written;
    remaining -= n_written;
  }
  return true;
}

static json_object *_read_message(WayfireSocket *sock, char **error) {
  uint32_t rlen_le;
  if (!_read_exact(sock->fd, &rlen_le, sizeof(uint32_t), error)) {
    return NULL;
  }
  uint32_t rlen = le32toh(rlen_le);

  if (rlen == 0) {
    set_error(error, "Received empty 0-length message.");
    return NULL;
  }

  char *buf = (char *)malloc(rlen + 1);
  if (!buf) {
    set_error(error, "Failed to allocate memory for message buffer.");
    return NULL;
  }

  if (!_read_exact(sock->fd, buf, rlen, error)) {
    free(buf);
    return NULL;
  }
  buf[rlen] = '\0';

  json_object *jobj = json_tokener_parse(buf);
  free(buf);

  if (!jobj) {
    set_error(error, "Failed to parse JSON response.");
    return NULL;
  }

  json_object *jerror;
  if (json_object_object_get_ex(jobj, "error", &jerror)) {
    const char *err_str = json_object_get_string(jerror);
    set_error(error, err_str);
    json_object_put(jobj);
    return NULL;
  }
  return jobj;
}

static void _find_sockets_in_dir(WfPathNode **head, const char *dir_path) {
  DIR *d = opendir(dir_path);
  if (!d)
    return;
  struct dirent *dir;
  while ((dir = readdir(d)) != NULL) {
    const char *name = dir->d_name;
    if (strncmp(name, "wayfire-wayland-", 16) == 0 &&
        strstr(name, ".socket") != NULL &&
        strcmp(strstr(name, ".socket"), ".socket") == 0) {
      char full_path[1024];
      snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
      path_list_add(head, full_path);
    }
  }
  closedir(d);
}

static WfPathNode *_find_candidate_sockets() {
  WfPathNode *head = NULL;
  const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
  if (runtime_dir) {
    _find_sockets_in_dir(&head, runtime_dir);
  }
  _find_sockets_in_dir(&head, "/tmp");
  return head;
}

static int _connect_client(const char *socket_name, char **error) {
  int fd;
  struct sockaddr_un addr;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    set_error(error, "Failed to create socket");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_name, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    close(fd);
    set_error(error, "Failed to connect to socket");
    return -1;
  }
  return fd;
}

WayfireSocket *wayfire_socket_create(const char *socket_name,
                                     bool allow_manual_search, char **error) {
  WayfireSocket *sock = (WayfireSocket *)calloc(1, sizeof(WayfireSocket));
  if (!sock) {
    set_error(error, "Failed to allocate WayfireSocket");
    return NULL;
  }
  sock->fd = -1;

  char *target_socket_name = (char *)socket_name;
  char *env_socket_name = NULL;

  if (target_socket_name == NULL) {
    const char *env_val = getenv("WAYFIRE_SOCKET");
    if (env_val) {
      env_socket_name = strdup(env_val);
      target_socket_name = env_socket_name;
    }
  }

  if (target_socket_name) {
    sock->fd = _connect_client(target_socket_name, NULL);
    if (sock->fd != -1) {
      sock->socket_name = strdup(target_socket_name);
    }
  }

  free(env_socket_name);

  if (sock->fd == -1 && allow_manual_search) {
    WfPathNode *candidates = _find_candidate_sockets();
    WfPathNode *current = candidates;
    while (current) {
      sock->fd = _connect_client(current->path, NULL);
      if (sock->fd != -1) {
        sock->socket_name = strdup(current->path);
        break;
      }
      current = current->next;
    }
    path_list_free(candidates);
  }

  if (sock->fd == -1) {
    set_error(error, "Failed to find or connect to a suitable Wayfire socket.");
    free(sock);
    return NULL;
  }
  return sock;
}

void wayfire_socket_destroy(WayfireSocket *sock) {
  if (sock) {
    if (sock->fd != -1) {
      close(sock->fd);
    }
    free(sock->socket_name);
    while (sock->pending_events_head) {
      json_object_put(event_list_dequeue(sock));
    }
    free(sock);
  }
}

bool wayfire_socket_is_connected(WayfireSocket *sock) {
  return sock && sock->fd != -1;
}

json_object *wayfire_socket_send_json(WayfireSocket *sock, json_object *msg,
                                      char **error) {
  if (!sock || sock->fd == -1) {
    set_error(error, "Socket not connected.");
    return NULL;
  }

  const char *data_str = json_object_to_json_string(msg);
  if (!data_str) {
    set_error(error, "Failed to serialize JSON message.");
    return NULL;
  }
  size_t len = strlen(data_str);
  uint32_t len_le = htole32(len);

  if (!_write_exact(sock->fd, &len_le, sizeof(uint32_t), error)) {
    return NULL;
  }
  if (!_write_exact(sock->fd, data_str, len, error)) {
    return NULL;
  }

  while (true) {
    json_object *response = _read_message(sock, error);
    if (!response) {
      return NULL;
    }

    json_object *event_field;
    if (json_object_object_get_ex(response, "event", &event_field)) {
      event_list_queue(sock, response);
      continue;
    } else {
      return response;
    }
  }
}

json_object *wayfire_socket_read_next_event(WayfireSocket *sock, char **error) {
  json_object *event = event_list_dequeue(sock);
  if (event) {
    return event;
  }
  return _read_message(sock, error);
}

static json_object *create_simple_message(const char *method) {
  json_object *msg = json_object_new_object();
  json_object_object_add(msg, "method", json_object_new_string(method));
  return msg;
}

json_object *wayfire_socket_list_methods(WayfireSocket *sock, char **error) {
  json_object *msg = create_simple_message("list-methods");
  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);
  return response;
}

json_object *wayfire_socket_list_views(WayfireSocket *sock,
                                       bool filter_mapped_toplevel,
                                       char **error) {
  json_object *msg = create_simple_message("window-rules/list-views");
  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);

  if (!response || !filter_mapped_toplevel) {
    return response;
  }

  if (json_object_get_type(response) != json_type_array) {
    return response;
  }

  json_object *filtered_array = json_object_new_array();
  size_t len = json_object_array_length(response);
  for (size_t i = 0; i < len; ++i) {
    json_object *v = json_object_array_get_idx(response, i);

    json_object *jmapped, *jrole, *jpid;
    bool mapped = json_object_object_get_ex(v, "mapped", &jmapped) &&
                  json_object_get_boolean(jmapped);
    const char *role = json_object_object_get_ex(v, "role", &jrole)
                           ? json_object_get_string(jrole)
                           : "";
    int pid = json_object_object_get_ex(v, "pid", &jpid)
                  ? json_object_get_int(jpid)
                  : -1;

    if (mapped && strcmp(role, "desktop-environment") != 0 && pid != -1) {
      json_object_get(v);
      json_object_array_add(filtered_array, v);
    }
  }

  json_object_put(response);
  return filtered_array;
}

json_object *wayfire_socket_get_option_value(WayfireSocket *sock,
                                             const char *option, char **error) {
  json_object *msg = create_simple_message("wayfire/get-config-option");
  json_object *data = json_object_new_object();
  json_object_object_add(data, "option", json_object_new_string(option));
  json_object_object_add(msg, "data", data);

  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);
  return response;
}

json_object *wayfire_socket_set_focus(WayfireSocket *sock, int view_id,
                                      char **error) {
  json_object *msg = create_simple_message("window-rules/focus-view");
  json_object *data = json_object_new_object();
  json_object_object_add(data, "id", json_object_new_int(view_id));
  json_object_object_add(msg, "data", data);

  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);
  return response;
}

json_object *wayfire_socket_get_focused_view(WayfireSocket *sock,
                                             char **error) {
  json_object *msg = create_simple_message("window-rules/get-focused-view");
  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);
  return response;
}

json_object *wayfire_socket_get_cursor_position(WayfireSocket *sock,
                                                char **error) {
  json_object *msg = create_simple_message("window-rules/get_cursor_position");
  json_object *response = wayfire_socket_send_json(sock, msg, error);
  json_object_put(msg);
  return response;
}

const char *wayfire_socket_get_socket_name(WayfireSocket *sock) {
  if (sock) {
    return sock->socket_name;
  }
  return NULL;
}
