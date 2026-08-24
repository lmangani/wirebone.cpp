#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wirebone_coordinator wirebone_coordinator;

typedef struct wirebone_config {
    const char* listen;      /* "0.0.0.0:8080" */
    const char* server_url;  /* advertised control URL */
    const char* ip_prefix;
    const char* ipv6_prefix;
    const char* state_path;
    const char* domain;
    const char* dns_listen;  /* "0.0.0.0:5353" or empty to disable */
} wirebone_config;

typedef struct wirebone_node_info {
    uint64_t id;
    char* hostname;
    char* ipv4;
    char* ipv6;
    char* node_key;
    int online;
} wirebone_node_info;

wirebone_coordinator* wirebone_create(const wirebone_config* cfg);
void wirebone_destroy(wirebone_coordinator* c);

/* Start in a background thread. Returns 0 on success. */
int wirebone_start(wirebone_coordinator* c);
void wirebone_stop(wirebone_coordinator* c);
int wirebone_running(const wirebone_coordinator* c);

/* Caller must free() the returned string. */
char* wirebone_bound_address(const wirebone_coordinator* c);
char* wirebone_bootstrap_key(const wirebone_coordinator* c);
char* wirebone_create_preauth_key(wirebone_coordinator* c, int reusable, int ephemeral);
char* wirebone_noise_public_key(const wirebone_coordinator* c);

/* Caller must wirebone_free_nodes() the returned array. count may be 0. */
wirebone_node_info* wirebone_list_nodes(const wirebone_coordinator* c, size_t* count);
void wirebone_free_nodes(wirebone_node_info* nodes, size_t count);

/* Full coordinator snapshot (JSON). Caller must free() the string. */
char* wirebone_export_state(const wirebone_coordinator* c);
int wirebone_import_state(wirebone_coordinator* c, const char* json);

/* Invoked after every durable mutation. json is valid only for the duration of the call. */
typedef void (*wirebone_persist_cb)(const char* json, void* user);
void wirebone_set_persist_callback(wirebone_coordinator* c, wirebone_persist_cb cb, void* user);
int wirebone_persist(wirebone_coordinator* c);

#ifdef __cplusplus
}
#endif
