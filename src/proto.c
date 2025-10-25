
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
    struct tm pt_tm;
    int pt_offset;
    if (proto_parse_pt(in_line, &pt_tm, &pt_offset) < 0) {
        return snprintf(out_line, outsz, "ERROR:PARSE_FAILED");
    }
    struct tm et_tm;
    int et_offset;
    if (convert_pt_to_et(&pt_tm, &et_tm, &et_offset) < 0) {
        return snprintf(out_line, outsz, "ERROR:CONVERT_FAILED");
    }
    return proto_format_et(out_line, outsz, &et_tm, et_offset);
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

// proto_parse_pt: parse "PT yyyy-mm-ddTHH:MM:SS±HH:MM"
int proto_parse_pt(const char* line, struct tm* out_tm, int* out_offset_minutes) {
    int y, mo, d, h, mi, s, off_h, off_m;
    char sign_char;
    if (sscanf(line, "PT %d-%d-%dT%d:%d:%d%c%d:%d", &y, &mo, &d, &h, &mi, &s, &sign_char, &off_h, &off_m) != 9) {
        return -1;
    }
    memset(out_tm, 0, sizeof(*out_tm));
    out_tm->tm_year = y - 1900;
    out_tm->tm_mon = mo - 1;
    out_tm->tm_mday = d;
    out_tm->tm_hour = h;
    out_tm->tm_min = mi;
    out_tm->tm_sec = s;
    out_tm->tm_isdst = -1;
    int sign = (sign_char == '-') ? -1 : 1;
    *out_offset_minutes = sign * (off_h * 60 + off_m);
    return 0;
}

// proto_format_et: format ET message "ET yyyy-mm-ddTHH:MM:SS±HH:MM"
int proto_format_et(char* out, size_t outsz, const struct tm* et_tm, int utc_offset_minutes) {
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

    int written = snprintf(out, outsz, "ET:%04d-%02d-%02dT%02d:%02d:%02d%s",        // Stores the ET format in out buffer
                           et_tm->tm_year + 1900, et_tm->tm_mon + 1, et_tm->tm_mday,
                           et_tm->tm_hour, et_tm->tm_min, et_tm->tm_sec,
                           offbuf);
    return (written >= (int)outsz) ? -1 : written;  // Checks if written is larger than the size of the buffer, if so error occured.
}

// convert_pt_to_et: Convert PT time to ET time
int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes) {
    // PT and ET are 3 hours apart (PT is UTC-8/-7, ET is UTC-5/-4)
    // Add 3 hours to PT wall-clock time to get ET wall-clock time
    struct tm et_tm = *pt_tm_in;
    et_tm.tm_hour += 3;
    
    // Normalize the time (handle hour overflow)
    time_t temp = mktime(&et_tm);
    if (temp == -1) return -1;
    
    struct tm* normalized = localtime(&temp);
    if (!normalized) return -1;
    
    *out_et_tm = *normalized;
    
    // ET is UTC-5 (standard) or UTC-4 (daylight)
    // Use same DST status as PT had
    *out_et_offset_minutes = (pt_tm_in->tm_isdst > 0) ? -240 : -300;
    return 0;
}