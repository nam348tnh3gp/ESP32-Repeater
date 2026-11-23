/*
 * apex_dns.h - DNS captive portal + forwarder dùng chung cho ESP-IDF và Arduino.
 *
 * So với bản cũ:
 *  - Header DNS đúng chuẩn: giữ QDCOUNT=1 khi trả lời (bản cũ memset(resp+4,0,8) làm QDCOUNT=0
 *    nhưng vẫn kèm question => gói sai định dạng).
 *  - Chỉ trả A cho truy vấn A; AAAA/loại khác của domain captive => NOERROR rỗng.
 *  - Domain captive khớp theo ranh giới nhãn ("evilwww.google.com" không còn khớp "www.google.com").
 *  - Forwarder KHÔNG chặn: bảng pending + select(), mỗi truy vấn chậm không làm kẹt client khác.
 *  - Ghi lại ID gốc, ID gửi lên upstream ngẫu nhiên, socket upstream riêng; chỉ nhận trả lời đúng
 *    (ID + địa chỉ + cổng upstream).
 *  - Upstream lấy từ DNS của uplink (STA) qua callback, fallback 8.8.8.8.
 *  - Chỉ lắng nghe trên địa chỉ AP (bind_addr) => không thành open-resolver cho mạng uplink.
 *  - Có wdt_kick, và không bao giờ "return" khỏi task theo kiểu làm crash FreeRTOS: hàm trả -1 để
 *    task bao ngoài tự retry.
 */
#ifndef APEX_DNS_H
#define APEX_DNS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef APEX_HOST_TEST
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <sys/select.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define APEX_DNS_BUF_SZ          1232
#define APEX_DNS_PENDING         8
#define APEX_DNS_PENDING_TTL_MS  2000
#define APEX_DNS_SELECT_US       250000
#define APEX_DNS_FALLBACK_IP     0x08080808u /* 8.8.8.8 (đối xứng byte nên không phụ thuộc endian) */

typedef struct {
    uint16_t port;                          /* 0 => 53 */
    uint32_t bind_addr;                     /* network order; 0 => INADDR_ANY */
    uint8_t  ap_ip[4];                      /* IP trả lời cho domain captive khi chưa có internet */
    uint16_t upstream_port;                 /* 0 => 53 */
    int      (*internet_ok)(void *ctx);
    uint32_t (*upstream_ip)(void *ctx);     /* network order; 0 => dùng fallback */
    uint32_t (*rand32)(void);               /* optional */
    void     (*wdt_kick)(void);             /* optional, gọi mỗi <= 250 ms */
    void     (*log)(const char *msg);       /* optional */
    void     *ctx;
    volatile int *stop;                     /* optional, dùng cho test */
} apex_dns_cfg_t;

typedef struct {
    uint8_t  used;
    uint16_t up_id;
    uint16_t orig_id;
    uint32_t deadline;
    struct sockaddr_in client;
    struct sockaddr_in upstream;
} apex_dns_pending_t;

static const char *const apex_dns_captive_domains[] = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "detectportal.firefox.com",
    "www.msftncsi.com",
    "captive.apple.com",
    "www.apple.com",
    "clients3.google.com",
    "nmcheck.gnome.org",
    "www.google.com",
    NULL
};

static inline uint32_t apex_dns_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

static inline uint32_t apex_dns_xorshift(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}

/* name: chữ thường, không có dấu chấm cuối. Khớp chính xác hoặc là subdomain thật sự. */
static inline int apex_dns_is_captive(const char *name) {
    size_t nl = strlen(name);
    for (int i = 0; apex_dns_captive_domains[i] != NULL; i++) {
        const char *d = apex_dns_captive_domains[i];
        size_t dl = strlen(d);
        if (nl == dl && memcmp(name, d, dl) == 0) return 1;
        if (nl > dl && name[nl - dl - 1] == '.' && memcmp(name + (nl - dl), d, dl) == 0) return 1;
    }
    return 0;
}

/* Phân tích gói truy vấn. Trả 0 nếu hợp lệ (QR=0, opcode QUERY, QDCOUNT=1, class IN, không nén). */
static inline int apex_dns_parse_question(const uint8_t *q, int len, char *name, size_t name_sz,
                                          int *q_end, uint16_t *qtype) {
    if (len < 12) return -1;
    if (q[2] & 0x80) return -1;
    if (((q[2] >> 3) & 0x0F) != 0) return -1;
    if (q[4] != 0 || q[5] != 1) return -1;
    int pos = 12;
    size_t o = 0;
    for (;;) {
        if (pos >= len) return -1;
        uint8_t l = q[pos++];
        if (l == 0) break;
        if (l & 0xC0) return -1;
        if (pos + (int)l > len) return -1;
        if (o + (size_t)l + 2 > name_sz) return -1;
        if (o) name[o++] = '.';
        for (int i = 0; i < (int)l; i++) {
            char c = (char)q[pos + i];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            name[o++] = c;
        }
        pos += l;
    }
    name[o] = '\0';
    if (pos + 4 > len) return -1;
    uint16_t qclass = (uint16_t)((q[pos + 2] << 8) | q[pos + 3]);
    if (qclass != 1) return -1;
    *qtype = (uint16_t)((q[pos] << 8) | q[pos + 1]);
    *q_end = pos + 4;
    return 0;
}

/* Dựng câu trả lời: copy header+question, QR=1, RA=1, giữ RD, QDCOUNT=1. */
static inline int apex_dns_build_reply(uint8_t *out, size_t out_sz, const uint8_t *q, int q_end,
                                       uint8_t rcode, int answer_a, const uint8_t ip[4]) {
    size_t need = (size_t)q_end + (answer_a ? 16u : 0u);
    if (need > out_sz) return -1;
    memcpy(out, q, (size_t)q_end);
    out[2] = (uint8_t)(0x80 | (q[2] & 0x01) | (answer_a ? 0x04 : 0x00));
    out[3] = (uint8_t)(0x80 | (rcode & 0x0F));
    out[4] = 0; out[5] = 1;
    out[6] = 0; out[7] = (uint8_t)(answer_a ? 1 : 0);
    out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
    int off = q_end;
    if (answer_a) {
        out[off++] = 0xC0; out[off++] = 0x0C;   /* name pointer -> offset 12 */
        out[off++] = 0x00; out[off++] = 0x01;   /* TYPE A */
        out[off++] = 0x00; out[off++] = 0x01;   /* CLASS IN */
        out[off++] = 0x00; out[off++] = 0x00; out[off++] = 0x00; out[off++] = 60; /* TTL */
        out[off++] = 0x00; out[off++] = 0x04;   /* RDLENGTH */
        memcpy(out + off, ip, 4);
        off += 4;
    }
    return off;
}

#define APEX_DNS_LOG(msg) do { if (cfg->log) cfg->log(msg); } while (0)

/* Chạy server DNS. Trả 0 khi cfg->stop được bật, -1 nếu lỗi khởi tạo socket. */
static inline int apex_dns_run(const apex_dns_cfg_t *cfg) {
    static uint8_t buf[APEX_DNS_BUF_SZ];
    static uint8_t out[512];
    static apex_dns_pending_t pend[APEX_DNS_PENDING];

    memset(pend, 0, sizeof(pend));

    int lsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (lsock < 0) { APEX_DNS_LOG("DNS: socket() that bai"); return -1; }
    int usock = socket(AF_INET, SOCK_DGRAM, 0);
    if (usock < 0) { APEX_DNS_LOG("DNS: socket upstream that bai"); close(lsock); return -1; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = cfg->bind_addr;
    a.sin_port = htons(cfg->port ? cfg->port : 53);
    if (bind(lsock, (struct sockaddr *)&a, sizeof(a)) < 0) {
        APEX_DNS_LOG("DNS: bind that bai");
        close(lsock); close(usock);
        return -1;
    }
    struct sockaddr_in ua;
    memset(&ua, 0, sizeof(ua));
    ua.sin_family = AF_INET;
    ua.sin_addr.s_addr = 0;
    ua.sin_port = 0;
    if (bind(usock, (struct sockaddr *)&ua, sizeof(ua)) < 0) {
        APEX_DNS_LOG("DNS: bind upstream that bai");
        close(lsock); close(usock);
        return -1;
    }

    uint32_t own_ip;
    memcpy(&own_ip, cfg->ap_ip, 4);
    uint32_t xs = apex_dns_now_ms() ^ 0x9E3779B9u;
    if (xs == 0) xs = 1;
    int maxfd = (lsock > usock ? lsock : usock) + 1;

    APEX_DNS_LOG("DNS captive portal san sang");

    while (!(cfg->stop && *cfg->stop)) {
        if (cfg->wdt_kick) cfg->wdt_kick();

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsock, &rfds);
        FD_SET(usock, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = APEX_DNS_SELECT_US;
        int n = select(maxfd, &rfds, NULL, NULL, &tv);

        uint32_t now = apex_dns_now_ms();
        for (int i = 0; i < APEX_DNS_PENDING; i++) {
            if (pend[i].used && (int32_t)(now - pend[i].deadline) >= 0) pend[i].used = 0;
        }
        if (n < 0) { usleep(50000); continue; }
        if (n == 0) continue;

        /* ---- trả lời từ upstream ---- */
        if (FD_ISSET(usock, &rfds)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int len = (int)recvfrom(usock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
            if (len >= 12 && (buf[2] & 0x80)) {
                uint16_t id = (uint16_t)((buf[0] << 8) | buf[1]);
                for (int i = 0; i < APEX_DNS_PENDING; i++) {
                    if (pend[i].used && pend[i].up_id == id &&
                        from.sin_addr.s_addr == pend[i].upstream.sin_addr.s_addr &&
                        from.sin_port == pend[i].upstream.sin_port) {
                        buf[0] = (uint8_t)(pend[i].orig_id >> 8);
                        buf[1] = (uint8_t)(pend[i].orig_id & 0xFF);
                        sendto(lsock, buf, (size_t)len, 0,
                               (struct sockaddr *)&pend[i].client, sizeof(pend[i].client));
                        pend[i].used = 0;
                        break;
                    }
                }
            }
        }

        /* ---- truy vấn từ client ---- */
        if (FD_ISSET(lsock, &rfds)) {
            struct sockaddr_in cl;
            socklen_t cll = sizeof(cl);
            int len = (int)recvfrom(lsock, buf, sizeof(buf), 0, (struct sockaddr *)&cl, &cll);
            if (len < 12 || (buf[2] & 0x80)) continue;

            if (cfg->internet_ok && cfg->internet_ok(cfg->ctx)) {
                uint32_t up = cfg->upstream_ip ? cfg->upstream_ip(cfg->ctx) : 0;
                if (up == 0 || up == own_ip) up = APEX_DNS_FALLBACK_IP;

                int slot = -1;
                for (int i = 0; i < APEX_DNS_PENDING; i++) {
                    if (!pend[i].used) { slot = i; break; }
                }
                if (slot < 0) {
                    /* bảng đầy: báo SERVFAIL để client thử lại thay vì im lặng */
                    char nm[256]; int qe; uint16_t qt;
                    if (apex_dns_parse_question(buf, len, nm, sizeof(nm), &qe, &qt) == 0) {
                        int rl = apex_dns_build_reply(out, sizeof(out), buf, qe, 2, 0, cfg->ap_ip);
                        if (rl > 0) sendto(lsock, out, (size_t)rl, 0, (struct sockaddr *)&cl, cll);
                    }
                    continue;
                }

                uint16_t up_id = 0;
                for (int tries = 0; tries < 8; tries++) {
                    up_id = cfg->rand32 ? (uint16_t)cfg->rand32() : (uint16_t)apex_dns_xorshift(&xs);
                    int clash = 0;
                    for (int i = 0; i < APEX_DNS_PENDING; i++) {
                        if (pend[i].used && pend[i].up_id == up_id) { clash = 1; break; }
                    }
                    if (!clash) break;
                }

                pend[slot].used = 1;
                pend[slot].up_id = up_id;
                pend[slot].orig_id = (uint16_t)((buf[0] << 8) | buf[1]);
                pend[slot].deadline = apex_dns_now_ms() + APEX_DNS_PENDING_TTL_MS;
                pend[slot].client = cl;
                memset(&pend[slot].upstream, 0, sizeof(pend[slot].upstream));
                pend[slot].upstream.sin_family = AF_INET;
                pend[slot].upstream.sin_addr.s_addr = up;
                pend[slot].upstream.sin_port = htons(cfg->upstream_port ? cfg->upstream_port : 53);

                buf[0] = (uint8_t)(up_id >> 8);
                buf[1] = (uint8_t)(up_id & 0xFF);
                if (sendto(usock, buf, (size_t)len, 0, (struct sockaddr *)&pend[slot].upstream,
                           sizeof(pend[slot].upstream)) < 0) {
                    pend[slot].used = 0;
                }
            } else {
                char nm[256];
                int qe = 0;
                uint16_t qt = 0;
                if (apex_dns_parse_question(buf, len, nm, sizeof(nm), &qe, &qt) != 0) continue;
                int rl;
                if (apex_dns_is_captive(nm)) {
                    rl = apex_dns_build_reply(out, sizeof(out), buf, qe, 0, qt == 1, cfg->ap_ip);
                } else {
                    rl = apex_dns_build_reply(out, sizeof(out), buf, qe, 2 /* SERVFAIL */, 0, cfg->ap_ip);
                }
                if (rl > 0) sendto(lsock, out, (size_t)rl, 0, (struct sockaddr *)&cl, cll);
            }
        }
    }

    close(lsock);
    close(usock);
    return 0;
}

#undef APEX_DNS_LOG

#ifdef __cplusplus
}
#endif

#endif /* APEX_DNS_H */
