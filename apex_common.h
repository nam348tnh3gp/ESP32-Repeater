/*
 * apex_common.h - các hàm dùng chung cho cả ESP-IDF (main/main.c) và Arduino (ESP_Code.ino).
 * Header-only, C99/C++ thuần, không phụ thuộc ESP-IDF => có thể test trên máy host (xem tests/).
 */
#ifndef APEX_COMMON_H
#define APEX_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_VERSION "22.4.0"

#define APEX_DEFAULT_AP_SSID "APEX_ULTRA"
#define APEX_DEFAULT_AP_PASS "12345678"

#define APEX_SSID_MAX 32   /* byte, theo chuẩn 802.11 */
#define APEX_PASS_MAX 63   /* WPA2-PSK passphrase */
#define APEX_PASS_MIN 8

/* Ngưỡng heap có độ trễ (hysteresis): tắt NAT khi < CRITICAL, chỉ bật lại khi > RECOVER.
 * Tránh hiện tượng bật/tắt NAT liên tục quanh một ngưỡng duy nhất. */
#define APEX_MEM_CRITICAL_BYTES 26000u
#define APEX_MEM_RECOVER_BYTES  40000u

/* So sánh chuỗi trong thời gian không phụ thuộc vị trí byte khác nhau đầu tiên. */
static inline int apex_ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    size_t n = la > lb ? la : lb;
    unsigned char diff = (unsigned char)(la != lb);
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (i < la) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < lb) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}

/* SSID hợp lệ: 1..32 byte, không có ký tự điều khiển. */
static inline int apex_valid_ssid(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > APEX_SSID_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 0;
    }
    return 1;
}

/* Mật khẩu WPA2: 8..63 ký tự (dùng cho AP, và cho STA khi mạng có mật khẩu). */
static inline int apex_valid_wpa_pass(const char *s) {
    size_t n = strlen(s);
    return n >= APEX_PASS_MIN && n <= APEX_PASS_MAX;
}

/* Trả về trạng thái "đang thiếu RAM" mới, có hysteresis. */
static inline int apex_mem_pressure(int prev, uint32_t free_bytes) {
    if (free_bytes < APEX_MEM_CRITICAL_BYTES) return 1;
    if (free_bytes > APEX_MEM_RECOVER_BYTES) return 0;
    return prev;
}

/* Escape chuỗi để đặt vào trong "..." của JSON. Luôn kết thúc bằng NUL.
 * Trả về 1 nếu đủ chỗ, 0 nếu bị cắt. */
static inline int apex_json_escape(char *dst, size_t dst_sz, const char *src) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    int ok = 1;
    if (dst_sz == 0) return 0;
    for (; *src; src++) {
        unsigned char c = (unsigned char)*src;
        char tmp[6];
        size_t tl = 0;
        if (c == '"' || c == '\\') { tmp[0] = '\\'; tmp[1] = (char)c; tl = 2; }
        else if (c == '\n') { tmp[0] = '\\'; tmp[1] = 'n'; tl = 2; }
        else if (c == '\r') { tmp[0] = '\\'; tmp[1] = 'r'; tl = 2; }
        else if (c == '\t') { tmp[0] = '\\'; tmp[1] = 't'; tl = 2; }
        else if (c < 0x20 || c == 0x7f) {
            tmp[0] = '\\'; tmp[1] = 'u'; tmp[2] = '0'; tmp[3] = '0';
            tmp[4] = hex[c >> 4]; tmp[5] = hex[c & 15]; tl = 6;
        } else { tmp[0] = (char)c; tl = 1; }
        if (o + tl + 1 > dst_sz) { ok = 0; break; }
        memcpy(dst + o, tmp, tl);
        o += tl;
    }
    dst[o] = '\0';
    return ok;
}

static inline int apex_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Lấy giá trị của `key` trong body application/x-www-form-urlencoded (đã NUL-terminated),
 * giải mã %XX và '+'. Kích thước kiểm tra trên chuỗi ĐÃ giải mã.
 * Trả về: 1 = tìm thấy, 0 = không có key, -1 = giá trị dài hơn out_sz-1 (hoặc out_sz == 0). */
static inline int apex_form_get(const char *body, const char *key, char *out, size_t out_sz) {
    size_t klen = strlen(key);
    const char *p = body;
    if (out_sz == 0) return -1;
    out[0] = '\0';
    while (*p) {
        const char *end = strchr(p, '&');
        size_t pair_len = end ? (size_t)(end - p) : strlen(p);
        const char *eq = (const char *)memchr(p, '=', pair_len);
        size_t this_klen = eq ? (size_t)(eq - p) : pair_len;
        if (this_klen == klen && memcmp(p, key, klen) == 0) {
            const char *v = eq ? eq + 1 : p + pair_len;
            const char *vend = p + pair_len;
            size_t o = 0;
            while (v < vend) {
                char ch;
                if (*v == '%' && (vend - v) >= 3 &&
                    apex_hexval(v[1]) >= 0 && apex_hexval(v[2]) >= 0) {
                    ch = (char)((apex_hexval(v[1]) << 4) | apex_hexval(v[2]));
                    v += 3;
                } else if (*v == '+') {
                    ch = ' ';
                    v++;
                } else {
                    ch = *v++;
                }
                if (o + 1 >= out_sz) { out[o] = '\0'; return -1; }
                out[o++] = ch;
            }
            out[o] = '\0';
            return 1;
        }
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* APEX_COMMON_H */
