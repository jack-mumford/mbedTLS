
#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <time.h>


// ---------------- Baseline: TLS ECHO ----------------

// Build a simple message for the echo baseline.
// TODO: (Optional) change the payload content (e.g., include your name or a counter).
int proto_build_client_message(char* out, size_t outsz) {
    // Use TZ (time zone) to obtain PT localtime and its offset.
    const char* old_tz = getenv("TZ");
    if (old_tz) old_tz = strdup(old_tz); // strdup so we can restore later

    setenv("TZ", "America/Los_Angeles", 1); // Use PT time zone
    tzset();

    // Sets now to current UTC time in secs
    time_t now = time(NULL);
    struct tm pt_tm;
    // Converts now to local time and stores it in the new struct
    localtime_r(&now, &pt_tm);

    // tm_gmtoff is seconds east of UTC. For -07:00 it will be negative.
    int offset_minutes = (int)(pt_tm.tm_gmtoff / 60);

    // Produces string to store correct time
    int r = proto_format_pt(out, outsz, &pt_tm, offset_minutes);

    // restore TZ
    if (old_tz) { setenv("TZ", old_tz, 1); free((void*)old_tz); } else { unsetenv("TZ"); }
    tzset();

    // Returns length of formatted string of -1 if error
    return r;
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    // We'll attempt to parse a PT message. If it parses, convert to ET. If not, echo back.
    struct tm pt_tm;
    int pt_offset_min;
    if (proto_parse_pt(in_line, &pt_tm, &pt_offset_min) == 0) { // If parsing works lets convert to ET, if not echo back
        struct tm et_tm;
        int et_offset_min;
        if (convert_pt_to_et(&pt_tm, pt_offset_min, &et_tm, &et_offset_min) == 0) { // Tries to convert to ET, returns 0 on success
            if (proto_format_et(out_line, outsz, &et_tm, et_offset_min) >= 0) return 0; //Formats ET to output buffer
        }
        // conversion failed -> produce an error text line
        snprintf(out_line, outsz, "ERROR conversion failed"); // Error message if conversion failed
        return 0;
    } else {
        // not a PT line -> echo
        snprintf(out_line, outsz, "%s", in_line);
        return 0;
    }
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
    if (!line || strncmp(line, "PT ", 3) != 0) return -1;   // Sees if the line begins with "PT " and is not null
    const char* p = line + 3;   // Skips PT prefix

    // We expect at least "YYYY-MM-DDTHH:MM:SS" (19 chars) + sign + hh:mm (6) => min length 26
    if ((int)strlen(p) < 25) return -1;

    // parse date/time part
    int yr, mon, day, hour, min, sec;
    char rest[16];
    // read first 19 chars into format, put remainder into rest
    int consumed = 0;

    // Extracts the values from the inputed string p        // Rest will store the UTC offset
    if (sscanf(p, "%4d-%2d-%2dT%2d:%2d:%2d%15s%n", &yr, &mon, &day, &hour, &min, &sec, rest, &consumed) < 6) {
        return -1;
    }

    // rest now contains ±HH:MM or maybe third token
    // If rest begins with +/- parse offset
    int off_sign = (rest[0] == '-') ? -1 : 1;   // Checks if UTC offset is negative
    int off_hr, off_min;
    if (sscanf(rest+1, "%2d:%2d", &off_hr, &off_min) != 2) return -1;   // Reads hour and minute of UTC offset
    *out_offset_minutes = off_sign * (off_hr*60 + off_min); // Saves the total amount of UTC offset in minutes

    out_tm->tm_year = yr - 1900;   // tm_year counts from 1900
    out_tm->tm_mon  = mon - 1;     // tm_mon is 0-based (0-11)
    out_tm->tm_mday = day;
    out_tm->tm_hour = hour;
    out_tm->tm_min  = min;
    out_tm->tm_sec  = sec;
    out_tm->tm_isdst = -1;         // usually -1 if unknown

    // Note: tm_isdst left unspecified (mktime/timegm will handle)
    return 0;
}
