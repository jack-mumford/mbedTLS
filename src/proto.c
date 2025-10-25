
#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <time.h>


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

// proto_format_pt: format PT message "PT yyyy-mm-ddTHH:MM:SS±HH:MM"
int proto_format_pt(char* out, size_t outsz, const struct tm* pt_tm, int utc_offset_minutes) {
    char offbuf[8];
    int offset = utc_offset_minutes;
    char sign = '+';
    if (offset < 0) {   // If the utc offset is negative update sign and convert to positive int
        sign = '-';
        offset = -offset;
    }
    int hours = offset / 60;
    int minutes = offset % 60;
    snprintf(offbuf, sizeof(offbuf), "%c%02d:%02d", sign, hours, minutes);  // print to buffer with specific size and format

    int written = snprintf(out, outsz, "PT %04d-%02d-%02dT%02d:%02d:%02d%s",        // Stores the PT format in out buffer
                           pt_tm->tm_year + 1900, pt_tm->tm_mon + 1, pt_tm->tm_mday,
                           pt_tm->tm_hour, pt_tm->tm_min, pt_tm->tm_sec,
                           offbuf);
    return (written >= (int)outsz) ? -1 : written;  // Checks if written is larger than the size of the buffer, if so error occured.
}