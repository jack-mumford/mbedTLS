
#pragma once
#include <stddef.h>

// Baseline: ECHO protocol
int proto_build_client_message(char* out, size_t outsz);
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz);

// --------- TODOs for Time Converter ---------
// Define message formats and helpers for PT->ET conversion:
// int proto_format_pt(char* out, size_t outsz, const struct tm* pt_tm, int utc_offset_minutes);
// int proto_parse_pt(const char* line, struct tm* out_tm, int* out_offset_minutes);
// int proto_format_et(char* out, size_t outsz, const struct tm* et_tm, int utc_offset_minutes);
// int proto_parse_et(const char* line, struct tm* out_tm, int* out_offset_minutes);
// int convert_pt_to_et(const struct tm* pt_tm_in, struct tm* out_et_tm, int* out_et_offset_minutes);
