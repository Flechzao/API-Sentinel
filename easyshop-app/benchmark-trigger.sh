#!/bin/bash
# easyshop-app 全量流量触发脚本
# 用途：通过 Burp 代理触发所有 53 个评分端点 + 基础设施端点
# 使用：bash benchmark-trigger.sh
# 前提：Burp 代理在 127.0.0.1:8080，easyshop-app 在 localhost:8089

set -e

BURP=http://127.0.0.1:8080
BASE=http://localhost:8089
COOKIE_DIR=/tmp/easyshop-cookies

mkdir -p "$COOKIE_DIR"

echo "=========================================="
echo " easyshop-app Benchmark Traffic Generator"
echo "=========================================="
echo ""

# === 0. Reset data first ===
echo "[0/6] Resetting benchmark data..."
curl -x $BURP -s -X POST "$BASE/api/admin/reset" -b "SESSION_USER=1" > /dev/null 2>&1
echo "  ✓ Data reset"
echo ""

# === 1. Login (get cookies for alice and bob) ===
echo "[1/6] Logging in test users..."
curl -x $BURP -s -c "$COOKIE_DIR/alice.cookie" -X POST "$BASE/api/login?username=alice" > /dev/null 2>&1
curl -x $BURP -s -c "$COOKIE_DIR/bob.cookie" -X POST "$BASE/api/login?username=bob" > /dev/null 2>&1
curl -x $BURP -s -c "$COOKIE_DIR/admin.cookie" -X POST "$BASE/api/login?username=admin" > /dev/null 2>&1
echo "  ✓ alice, bob, admin logged in"
echo ""

# Helper: silent curl through Burp
get()  { curl -x $BURP -s -o /dev/null "$@"; }
post() { curl -x $BURP -s -o /dev/null -X POST "$@"; }
put()  { curl -x $BURP -s -o /dev/null -X PUT "$@"; }

echo "[2/6] Triggering GET endpoints..."

# #1 SQLi
get "$BASE/api/users/search?name=test"
get "$BASE/api/users/search?name=Widget'"

# #2 SQLi safe
get "$BASE/api/products/search?name=Widget"

# #3 Stack trace + #4 IDOR
get "$BASE/api/orders/9999"
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/orders/1001"
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/orders/1001"

# #5 IDOR safe
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/invoices/2001"
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/invoices/2001"

# #6 垂直越权
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/admin/users"

# #9 CORS *
get "$BASE/api/profile" -H "Origin: http://evil.com"

# #10 CORS Origin 反射
get "$BASE/api/profile2" -H "Origin: http://evil.com"

# #16 缺失安全头
get "$BASE/web/dashboard"

# #17 信息泄露
get "$BASE/api/users/1"
get "$BASE/api/users/2"

# #18 信息安全对照
get "$BASE/api/users/1/public"

# #19 调试信息泄露
get "$BASE/api/debug/config"

# #21 XSS
get "$BASE/api/greet?name=<script>alert(1)</script>"

# #22 XSS safe
get "$BASE/api/welcome?name=<script>alert(1)</script>"

# #23 SSTI
get "$BASE/api/render?template=\${7*7}"

# #24 SSTI safe
get "$BASE/api/preview?template=\${7*7}"

# #25 路径穿越
get "$BASE/api/files?path=../../../etc/passwd"

# #26 路径穿越 safe
get "$BASE/api/documents?path=../../../etc/passwd"

# #29 布尔盲注
get "$BASE/api/products/detail?id=1"
get "$BASE/api/products/detail?id=1%20AND%201=1"
get "$BASE/api/products/detail?id=1%20AND%201=2"

# #30 布尔盲注 safe
get "$BASE/api/product-info?id=1"

# #39 开放重定向
get "$BASE/api/redirect?url=http://evil.com"

# #40 重定向 safe
get "$BASE/api/goto?url=http://evil.com"

# #45 命令注入
get "$BASE/api/logs?file=app.log;cat%20/etc/passwd"

# #46 命令注入 safe
get "$BASE/api/system-logs?file=app.log"

# #49 CRLF 注入
get "$BASE/api/download?filename=test%0d%0aX-Injected:evil"

# #50 CRLF safe
get "$BASE/api/fetch-file?filename=test"

# #53 Shadow API
get "$BASE/api/v0/users"
get "$BASE/api/v0/users/1"
get "$BASE/api/v0/debug"

echo "  ✓ GET endpoints triggered"
echo ""

echo "[3/6] Triggering POST endpoints..."

# #7 JWT alg:none
post "$BASE/api/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoxfQ."}'

# #8 JWT safe
post "$BASE/api/auth/verify" \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.abc"}'

# #11 SSRF
post "$BASE/api/fetch-url" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8089/api/debug/config"}'

# #12 SSRF safe
post "$BASE/api/fetch-external" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8089/api/debug/config"}'

# #13 危险文件上传
echo "test content" > /tmp/test-upload.jsp
post "$BASE/api/upload" \
  -F "file=@/tmp/test-upload.jsp"
rm -f /tmp/test-upload.jsp

# #14 上传 safe
echo "test image" > /tmp/test-upload.png
post "$BASE/api/upload-image" \
  -F "file=@/tmp/test-upload.png"
rm -f /tmp/test-upload.png

# #15 反序列化
post "$BASE/api/import" \
  -H "Content-Type: application/octet-stream" \
  -d 'fake-serialized-data'

# #20 CSRF (checkout)
post "$BASE/api/checkout" \
  -b "$COOKIE_DIR/alice.cookie" \
  -H "Content-Type: application/json" \
  -d '{"orderId":1001}'

# #27 XXE
post "$BASE/api/parse-xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# #28 XXE safe
post "$BASE/api/parse-config" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# #31 竞态条件
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{"toUser":"bob","amount":10}'

# #32 竞态条件 safe
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/wallet/transfer" \
  -H "Content-Type: application/json" \
  -d '{"toUser":"bob","amount":10}'

# #33 不安全随机数
post "$BASE/api/reset-token" \
  -H "Content-Type: application/json" \
  -d '{"userId":1}'

# #34 随机数 safe
post "$BASE/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"userId":1}'

# #35 硬编码密钥 + ECB
post "$BASE/api/encrypt" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world"}'

# #36 加密 safe
post "$BASE/api/seal" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world"}'

# #37 弱密码哈希
post "$BASE/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# #38 密码哈希 safe
post "$BASE/api/signup" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser2","password":"password123"}'

# #41 Mass Assignment
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/profile/update" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@evil.com","role":"admin"}'

# #42 Mass Assignment safe
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/profile/save" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@evil.com","role":"admin"}'

# #43 IDOR 修改订单 (bob 改 alice 的订单)
put -b "$COOKIE_DIR/bob.cookie" "$BASE/api/orders/1001/quantity" \
  -H "Content-Type: application/json" \
  -d '{"quantity":999}'

# #44 业务逻辑 (创建订单无校验)
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/orders" \
  -H "Content-Type: application/json" \
  -d '{"productId":1,"quantity":-5,"price":0.01}'

# #47 NoSQL 注入
post "$BASE/api/mongo/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# #48 NoSQL safe
post "$BASE/api/mongo/auth" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# #51 优惠券重放
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/coupon/apply" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10","orderTotal":100}'
# 再发一次测试重放
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/coupon/apply" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10","orderTotal":100}'

# #52 优惠券 safe
post -b "$COOKIE_DIR/alice.cookie" "$BASE/api/coupon/redeem" \
  -H "Content-Type: application/json" \
  -d '{"code":"VIP20","orderTotal":100}'

# Infrastructure endpoints
get "$BASE/api/health"
get "$BASE/api/stats"
get "$BASE/api/products/list"
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/orders/user/1"

# admin/secrets (feature test)
get "$BASE/api/admin/secrets"
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/admin/secrets"

echo "  ✓ POST endpoints triggered"
echo ""

echo "[4/6] Triggering IDOR cross-account traffic..."
# alice 访问自己的资源
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/orders/1001"
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/orders/1002"
get -b "$COOKIE_DIR/alice.cookie" "$BASE/api/users/1"
# bob 尝试访问 alice 的资源 (IDOR)
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/orders/1001"
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/orders/1002"
get -b "$COOKIE_DIR/bob.cookie" "$BASE/api/users/1"
# 匿名访问
get "$BASE/api/orders/1001"
get "$BASE/api/users/1"
echo "  ✓ Cross-account traffic generated"
echo ""

echo "[5/6] Triggering blind SQLi verification pairs..."
# Boolean blind pairs for #29
for i in $(seq 1 3); do
  get "$BASE/api/products/detail?id=$i"
  get "$BASE/api/products/detail?id=$i%20AND%201=1"
  get "$BASE/api/products/detail?id=$i%20AND%201=2"
done
echo "  ✓ Blind SQLi pairs triggered"
echo ""

echo "[6/6] Summary"
echo ""
echo "  All 53 scoring endpoints + infrastructure endpoints triggered."
echo "  Traffic routed through Burp proxy at $BURP"
echo "  Cookies saved to $COOKIE_DIR/"
echo ""
echo "  Next steps:"
echo "    1. Open Burp → Proxy → HTTP History → verify traffic"
echo "    2. In API-Sentinel, select endpoints → AI Analysis"
echo "    3. For no-source-code baseline: remove code repo config first"
echo ""
echo "  Done!"
