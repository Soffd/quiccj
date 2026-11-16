#include "Cangjie.h"
#include "smoke.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool run_get(CJTaskFunc entry, struct quiccj_smoke_request *request)
{
    CJThreadHandle task = RunCJTask(entry, request);
    if (task == NULL) {
        return false;
    }
    void *result = NULL;
    const int outcome = GetTaskRet(task, &result);
    ReleaseHandle(task);
    return outcome == E_OK && result == request;
}

static bool check_backend(CJTaskFunc entry, uint16_t port, const char *ca_file,
                          const char *other_ca, uint8_t backend)
{
    static const uint8_t expected[] = "hello from aioquic h3\n";
    const size_t expected_size = sizeof(expected) - 1;
    uint8_t body[sizeof(expected) + 1];
    memset(body, 0xda, sizeof(body));

    struct quiccj_smoke_request request = {
        .host = "127.0.0.1",
        .ca_file = ca_file,
        .body = body,
        .body_capacity = 1,
        .port = port,
        .backend = backend,
    };
    if (!run_get(entry, &request) || request.result != QUICCJ_BUFFER_TOO_SMALL ||
        request.status != 200 || request.body_size != expected_size) {
        fprintf(stderr, "short-buffer check failed (backend=%u, result=%d)\n",
                backend, request.result);
        return false;
    }
    for (size_t i = 0; i < sizeof(body); ++i) {
        if (body[i] != 0xda) {
            fprintf(stderr, "short-buffer request wrote to caller storage\n");
            return false;
        }
    }

    request.body_capacity = expected_size;
    if (!run_get(entry, &request) || request.result != QUICCJ_OK ||
        request.status != 200 || request.body_size != expected_size ||
        memcmp(body, expected, expected_size) != 0 || body[expected_size] != 0xda) {
        fprintf(stderr, "verified GET check failed (backend=%u, result=%d)\n",
                backend, request.result);
        return false;
    }

    request.ca_file = other_ca;
    if (!run_get(entry, &request) || request.result != QUICCJ_HANDSHAKE_FAILED ||
        request.status != 0 || request.body_size != 0) {
        fprintf(stderr, "certificate rejection check failed (backend=%u, result=%d)\n",
                backend, request.result);
        return false;
    }
    printf("C host -> Cangjie -> %s: status=200, body=%zu, short buffer and wrong CA verified\n",
           backend == QUICCJ_OPENSSL ? "OpenSSL" : "pure Cangjie", expected_size);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s BRIDGE_SO PORT CA_FILE OTHER_CA\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *end = NULL;
    const unsigned long port = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port\n");
        return EXIT_FAILURE;
    }

    const struct RuntimeParam config = {
        .logParam = { .logLevel = RTLOG_WARNING },
        .coParam = { .processorNum = 2 },
    };
    if (InitCJRuntime(&config) != E_OK) {
        fprintf(stderr, "could not initialize Cangjie runtime\n");
        return EXIT_FAILURE;
    }

    bool passed = false;
    if (LoadCJLibraryWithInit(argv[1]) == E_OK) {
        const CJTaskFunc entry = (CJTaskFunc)FindCJSymbol(argv[1], "quiccj_consumer_get");
        if (entry == NULL) {
            fprintf(stderr, "missing quiccj_consumer_get\n");
        } else {
            passed = check_backend(entry, (uint16_t)port, argv[3], argv[4], QUICCJ_PURE) &&
                     check_backend(entry, (uint16_t)port, argv[3], argv[4], QUICCJ_OPENSSL);
        }
    } else {
        fprintf(stderr, "could not load the Cangjie bridge\n");
    }
    // The bridge stays loaded until process exit.
    const int finalized = FiniCJRuntime();
    return passed && finalized == E_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
