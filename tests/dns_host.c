/* Server DNS chạy trên host để test apex_dns.h.
 * Dùng: dns_host <port> <upstream_port> <flagfile>
 *   flagfile chứa '1' => "có internet" (forward), khác => "chưa có internet" (captive).
 */
#define APEX_HOST_TEST 1
#include <stdio.h>
#include <signal.h>
#include "../apex_dns.h"

static const char *g_flag = NULL;
static volatile int g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static int inet_ok(void *ctx) {
    (void)ctx;
    FILE *f = fopen(g_flag, "r");
    if (!f) return 0;
    int c = fgetc(f);
    fclose(f);
    return c == '1';
}
static uint32_t upstream(void *ctx) { (void)ctx; return inet_addr("127.0.0.1"); }
static void lg(const char *m) { fprintf(stderr, "[dns] %s\n", m); }

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    g_flag = argv[3];
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);
    apex_dns_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port = (uint16_t)atoi(argv[1]);
    cfg.upstream_port = (uint16_t)atoi(argv[2]);
    cfg.bind_addr = inet_addr("127.0.0.1");
    cfg.ap_ip[0] = 192; cfg.ap_ip[1] = 168; cfg.ap_ip[2] = 4; cfg.ap_ip[3] = 1;
    cfg.internet_ok = inet_ok;
    cfg.upstream_ip = upstream;
    cfg.log = lg;
    cfg.stop = &g_stop;
    int r = apex_dns_run(&cfg);
    fprintf(stderr, "[dns] exit %d\n", r);
    return r == 0 ? 0 : 1;
}
