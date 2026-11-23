/* Unit test cho apex_common.h - chạy trên máy host: make -C tests (hoặc xem tests/run.sh) */
#include <stdio.h>
#include <assert.h>
#include "../apex_common.h"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

int main(void) {
    /* ct_equal */
    CHECK(apex_ct_equal("abc", "abc"));
    CHECK(!apex_ct_equal("abc", "abd"));
    CHECK(!apex_ct_equal("abc", "abcd"));
    CHECK(!apex_ct_equal("", "a"));
    CHECK(apex_ct_equal("", ""));

    /* ssid / pass */
    CHECK(apex_valid_ssid("A"));
    CHECK(!apex_valid_ssid(""));
    CHECK(apex_valid_ssid("12345678901234567890123456789012"));   /* 32 */
    CHECK(!apex_valid_ssid("123456789012345678901234567890123")); /* 33 */
    CHECK(!apex_valid_ssid("a\nb"));
    CHECK(apex_valid_wpa_pass("12345678"));
    CHECK(!apex_valid_wpa_pass("1234567"));
    CHECK(!apex_valid_wpa_pass("1234567890123456789012345678901234567890123456789012345678901234")); /* 64 */

    /* mem hysteresis */
    CHECK(apex_mem_pressure(0, 25000) == 1);
    CHECK(apex_mem_pressure(1, 30000) == 1);   /* giữ nguyên trong vùng đệm */
    CHECK(apex_mem_pressure(0, 30000) == 0);
    CHECK(apex_mem_pressure(1, 41000) == 0);

    /* json escape */
    char j[64];
    CHECK(apex_json_escape(j, sizeof j, "a\"b\\c\n") == 1);
    CHECK(strcmp(j, "a\\\"b\\\\c\\n") == 0);
    CHECK(apex_json_escape(j, sizeof j, "x\x01y") == 1);
    CHECK(strcmp(j, "x\\u0001y") == 0);
    char small[4];
    CHECK(apex_json_escape(small, sizeof small, "abcdef") == 0);
    CHECK(strlen(small) <= 3);

    /* form parsing */
    char v[16];
    CHECK(apex_form_get("ssid=Home&pass=p%40ss+w&token=abc", "pass", v, sizeof v) == 1);
    CHECK(strcmp(v, "p@ss w") == 0);
    CHECK(apex_form_get("ssid=Home&pass=x", "token", v, sizeof v) == 0);
    CHECK(apex_form_get("ssidx=1&ssid=2", "ssid", v, sizeof v) == 1 && strcmp(v, "2") == 0);  /* không khớp tiền tố */
    CHECK(apex_form_get("a=0123456789abcdef0123", "a", v, sizeof v) == -1);                    /* quá dài */
    CHECK(apex_form_get("a=%E1%BB%87", "a", v, sizeof v) == 1);                                /* UTF-8 3 byte */
    CHECK(strlen(v) == 3);
    CHECK(apex_form_get("a=%zz&b=1", "a", v, sizeof v) == 1 && strcmp(v, "%zz") == 0);          /* % hỏng giữ nguyên */
    CHECK(apex_form_get("a=%4", "a", v, sizeof v) == 1 && strcmp(v, "%4") == 0);                /* cụt cuối chuỗi */
    CHECK(apex_form_get("a=&b=2", "a", v, sizeof v) == 1 && v[0] == '\0');
    CHECK(apex_form_get("a", "a", v, sizeof v) == 1 && v[0] == '\0');
    CHECK(apex_form_get("", "a", v, sizeof v) == 0);
    CHECK(apex_form_get("a=1", "a", v, 0) == -1);

    /* SSID 32 byte toàn ký tự không-ASCII: mã hoá = 96 ký tự, giải mã = 32 byte phải vừa buffer 33 */
    char enc[200] = "ssid=";
    for (int i = 0; i < 32; i++) strcat(enc, "%E1");
    char big[33];
    CHECK(apex_form_get(enc, "ssid", big, sizeof big) == 1);
    CHECK(strlen(big) == 32);

    if (fails) { printf("%d FAILED\n", fails); return 1; }
    printf("test_common: OK\n");
    return 0;
}
