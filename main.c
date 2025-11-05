#include "wayfire_socket.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
  char *error = NULL;
  printf("Attempting to connect (sync C)...\n");

  WayfireSocket *sock = wayfire_socket_create(NULL, true, &error);

  if (error) {
    fprintf(stderr, "Error: %s\n", error);
    free(error);
    return 1;
  }

  printf("Connected to %s\n", wayfire_socket_get_socket_name(sock));

  // Example 1: List methods
  json_object *methods = wayfire_socket_list_methods(sock, &error);
  if (error) {
    fprintf(stderr, "Error (list_methods): %s\n", error);
    free(error);
  } else {
    printf("\nWayfire Methods:\n%s\n",
           json_object_to_json_string_ext(methods, JSON_C_TO_STRING_PRETTY));
    json_object_put(methods);
  }

  // Example 2: List views
  json_object *views = wayfire_socket_list_views(sock, true, &error);
  if (error) {
    fprintf(stderr, "Error (list_views): %s\n", error);
    free(error);
  } else {
    printf("\nFiltered Toplevel Views:\n%s\n",
           json_object_to_json_string_ext(views, JSON_C_TO_STRING_PRETTY));
    json_object_put(views);
  }

  // Example 3: Get cursor position
  json_object *pos = wayfire_socket_get_cursor_position(sock, &error);
  if (error) {
    fprintf(stderr, "Error (get_cursor_position): %s\n", error);
    free(error);
  } else {
    printf("\nCursor Position:\n%s\n",
           json_object_to_json_string_ext(pos, JSON_C_TO_STRING_PRETTY));
    json_object_put(pos);
  }

  wayfire_socket_destroy(sock);
  return 0;
}
