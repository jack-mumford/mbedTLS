
#include "proto.h"
#include <stdio.h>
#include <string.h>

// ---------------- Baseline: TLS ECHO ----------------

// Build a simple message for the echo baseline.
// TODO: (Optional) change the payload content (e.g., include your name or a counter).
int proto_build_client_message(char* out, size_t outsz) {
    return snprintf(out, outsz, "HELLO FROM CLIENT");
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    (void)outsz;
    return snprintf(out_line, outsz, "%s", in_line);
}

// Guidance for time-converter functions is in proto.h (see TODOs).
