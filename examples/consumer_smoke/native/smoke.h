#ifndef QUICCJ_CONSUMER_SMOKE_H
#define QUICCJ_CONSUMER_SMOKE_H

#include <stddef.h>
#include <stdint.h>

enum quiccj_smoke_backend { QUICCJ_PURE = 0, QUICCJ_OPENSSL = 1 };

enum quiccj_smoke_result {
    QUICCJ_OK = 0,
    QUICCJ_INVALID_ARGUMENT = 1,
    QUICCJ_HANDSHAKE_FAILED = 2,
    QUICCJ_BUFFER_TOO_SMALL = 3,
    QUICCJ_FAILED = 4
};

/* Inputs and output buffer remain owned by the caller until the task returns.
 * body_size reports the required size on QUICCJ_BUFFER_TOO_SMALL.
 */
struct quiccj_smoke_request {
    const char *host;
    const char *ca_file;
    uint8_t *body;
    size_t body_capacity;
    size_t body_size;
    int32_t status;
    int32_t result;
    uint16_t port;
    uint8_t backend;
};

#endif
