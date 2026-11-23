#!/usr/bin/env bash
# Chạy toàn bộ test trên máy host (không cần ESP32): ./tests/run.sh
# Yêu cầu: gcc, python3. Biên dịch kèm AddressSanitizer + UBSan.
set -euo pipefail
cd "$(dirname "$0")"
OUT="${TMPDIR:-/tmp}/apex_tests"
mkdir -p "$OUT"
CFLAGS="-Wall -Wextra -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer"

echo "== apex_common.h =="
gcc $CFLAGS -o "$OUT/test_common" test_common.c
"$OUT/test_common"

echo "== apex_dns.h (server thật trên loopback) =="
gcc $CFLAGS -o "$OUT/dns_host" dns_host.c
python3 test_dns.py "$OUT/dns_host"

echo "== apex_ui.h (header biên dịch được dưới C và C++) =="
printf '#include "apex_ui.h"\nint main(void){return APEX_INDEX_HTML[0]!=0?0:1;}\n' > "$OUT/ui.c"
gcc  -Wall -Wextra -Werror -I.. -o "$OUT/ui_c"   "$OUT/ui.c"   && "$OUT/ui_c"
g++  -Wall -Wextra -Werror -I.. -x c++ -o "$OUT/ui_cpp" "$OUT/ui.c" && "$OUT/ui_cpp"
echo "ALL TESTS PASSED"
