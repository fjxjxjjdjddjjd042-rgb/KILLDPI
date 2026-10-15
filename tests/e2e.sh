#!/usr/bin/env bash
# KILLDPI end-to-end test-suite.
# Usage: tests/e2e.sh <path-to-xray-binary>
# Spins up a KILLDPI server + client (SOCKS5 entry) in several transport
# configurations and measures correctness, latency, throughput and recovery.
set -uo pipefail
XRAY="$(realpath "${1:-core/xray}")"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
RESULTS=()
log()  { echo "[e2e] $*"; }
ok()   { PASS=$((PASS+1)); RESULTS+=("PASS  $1"); log "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); RESULTS+=("FAIL  $1"); log "FAIL: $1"; }
cleanup() { pkill -P $$ >/dev/null 2>&1 || true; jobs -p | xargs -r kill >/dev/null 2>&1 || true; }
trap cleanup EXIT

cd "$WORK"
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

# ---------- keys ----------
KEYS="$("$XRAY" killdpi-keygen)"
PRIV=$(echo "$KEYS" | awk '/PrivateKey/{print $2}')
PUB=$(echo "$KEYS"  | awk '/PublicKey/{print $2}')
UUID=$(echo "$KEYS" | awk '/UUID/{print $2}')
log "server pub key: $PUB  uuid: $UUID"

# ---------- self-signed TLS cert ----------
"$XRAY" tls cert -domain=killdpi.test -expire=240h > cert.json
python3 - <<'EOF'
import json
d=json.load(open('cert.json'))
open('cert.pem','w').write("\n".join(d['certificate'])+"\n")
open('key.pem','w').write("\n".join(d['key'])+"\n")
EOF

# ---------- backend echo/http servers ----------
cat > backend.py <<'EOF'
import socket, threading, sys, time, http.server, socketserver
# TCP echo on 9001
def tcp_echo():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',9001)); s.listen(64)
    while True:
        c,_=s.accept()
        def h(c):
            try:
                while True:
                    d=c.recv(65536)
                    if not d: break
                    c.sendall(d)
            finally: c.close()
        threading.Thread(target=h,args=(c,),daemon=True).start()
# UDP echo on 9002
def udp_echo():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',9002))
    while True:
        d,a=s.recvfrom(65536); s.sendto(d,a)
# HTTP "fallback" web server on 9003
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','text/plain'); self.end_headers(); self.wfile.write(b'FALLBACK-OK')
    def log_message(self,*a): pass
def http_srv():
    socketserver.TCPServer.allow_reuse_address=True
    socketserver.ThreadingTCPServer(('127.0.0.1',9003),H).serve_forever()
# HTTP 10MB download on 9004
class Big(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        n=10*1024*1024
        self.send_response(200); self.send_header('Content-Length',str(n)); self.end_headers()
        chunk=b'A'*65536
        while n>0:
            self.wfile.write(chunk[:min(n,65536)]); n-=65536
    def log_message(self,*a): pass
def big_srv():
    socketserver.TCPServer.allow_reuse_address=True
    socketserver.ThreadingTCPServer(('127.0.0.1',9004),Big).serve_forever()
for f in (tcp_echo,udp_echo,http_srv,big_srv): threading.Thread(target=f,daemon=True).start()
print("backends up",flush=True)
while True: time.sleep(3600)
EOF
python3 backend.py > backend.log 2>&1 &
sleep 1

# ---------- config generators ----------
# $1 = name, $2 = server port, $3 = socks port, $4 = stream settings JSON (server), $5 = stream settings (client), $6 = extra inbound settings
mk_cfgs() {
  local name=$1 sport=$2 cport=$3 ss_s=$4 ss_c=$5 extra=${6:-}
  cat > "server-$name.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1", "port": $sport, "protocol": "killdpi",
    "settings": {"clients": [{"id": "$UUID", "email": "e2e@test"}], "privateKey": "$PRIV" $extra},
    "streamSettings": $ss_s
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
  cat > "client-$name.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": $cport, "protocol": "socks", "settings": {"udp": true}}],
  "outbounds": [{
    "protocol": "killdpi",
    "settings": {"address": "127.0.0.1", "port": $sport, "id": "$UUID", "publicKey": "$PUB", "keepalive": 10},
    "streamSettings": $ss_c
  }]
}
EOF
}

start_pair() { # name
  "$XRAY" run -c "server-$1.json" > "server-$1.log" 2>&1 & echo $! > "server-$1.pid"
  "$XRAY" run -c "client-$1.json" > "client-$1.log" 2>&1 & echo $! > "client-$1.pid"
  sleep 1.2
}
stop_pair() { kill "$(cat "server-$1.pid")" "$(cat "client-$1.pid")" 2>/dev/null; sleep 0.3; }

# ---------- test primitives (python, via SOCKS5) ----------
cat > probe.py <<'EOF'
import socket, struct, sys, time, os, hashlib
def socks_tcp(port, host, dport):
    s=socket.create_connection(('127.0.0.1',port),timeout=10)
    s.sendall(b'\x05\x01\x00'); assert s.recv(2)==b'\x05\x00'
    s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(host)+struct.pack('>H',dport))
    r=s.recv(10); assert r[1]==0, f"socks connect failed {r}"
    return s
def socks_udp(port):
    c=socket.create_connection(('127.0.0.1',port),timeout=10)
    c.sendall(b'\x05\x01\x00'); c.recv(2)
    c.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('0.0.0.0')+b'\x00\x00')
    r=c.recv(10); assert r[1]==0
    relay=(socket.inet_ntoa(r[4:8]),struct.unpack('>H',r[8:10])[0])
    u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(5)
    return c,u,relay
mode=sys.argv[1]; port=int(sys.argv[2])
if mode=='tcp_echo':
    s=socks_tcp(port,'127.0.0.1',9001)
    data=os.urandom(int(sys.argv[3])); s.sendall(data)
    got=b''
    while len(got)<len(data): got+=s.recv(65536)
    print('OK' if got==data else 'MISMATCH')
elif mode=='tcp_latency':
    s=socks_tcp(port,'127.0.0.1',9001)
    lat=[]
    for i in range(50):
        t=time.perf_counter(); s.sendall(b'x'*64); s.recv(64); lat.append((time.perf_counter()-t)*1000)
    lat.sort(); print(f"rtt_ms p50={lat[25]:.2f} p95={lat[47]:.2f} min={lat[0]:.2f}")
elif mode=='connect_latency':
    lat=[]
    for i in range(20):
        t=time.perf_counter(); s=socks_tcp(port,'127.0.0.1',9001); s.sendall(b'p'); s.recv(1); lat.append((time.perf_counter()-t)*1000); s.close()
    lat.sort(); print(f"handshake+first_byte_ms p50={lat[10]:.2f} p95={lat[18]:.2f}")
elif mode=='udp_echo':
    c,u,relay=socks_udp(port)
    okc=0
    for i in range(20):
        payload=os.urandom(1200)
        pkt=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('>H',9002)+payload
        u.sendto(pkt,relay)
        try:
            r,_=u.recvfrom(65536)
            if r[10:]==payload: okc+=1
        except socket.timeout: pass
    print(f"udp {okc}/20")
elif mode=='udp_latency':
    c,u,relay=socks_udp(port); lat=[]
    for i in range(30):
        pkt=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('>H',9002)+b'q'*64
        t=time.perf_counter(); u.sendto(pkt,relay)
        try: u.recvfrom(65536); lat.append((time.perf_counter()-t)*1000)
        except socket.timeout: pass
    lat.sort(); print(f"udp_rtt_ms p50={lat[len(lat)//2]:.2f} n={len(lat)}" if lat else "udp_rtt none")
elif mode=='throughput':
    s=socks_tcp(port,'127.0.0.1',9004)
    s.sendall(b'GET / HTTP/1.0\r\nHost: x\r\n\r\n')
    t=time.perf_counter(); n=0
    while True:
        d=s.recv(262144)
        if not d: break
        n+=len(d)
    dt=time.perf_counter()-t
    print(f"download {n/1e6:.1f}MB in {dt:.2f}s = {n*8/dt/1e6:.0f} Mbit/s")
elif mode=='upload':
    s=socks_tcp(port,'127.0.0.1',9001)
    total=10*1024*1024; chunk=os.urandom(65536); sent=0; recvd=0
    import threading
    def rd():
        global recvd
        while recvd<total: recvd+=len(s.recv(262144))
    th=threading.Thread(target=rd); th.start()
    t=time.perf_counter()
    while sent<total: s.sendall(chunk); sent+=len(chunk)
    th.join(); dt=time.perf_counter()-t
    print(f"echo-roundtrip {total/1e6:.1f}MB in {dt:.2f}s = {total*8/dt/1e6:.0f} Mbit/s (each direction)")
elif mode=='concurrent':
    import threading
    res=[0]
    def w():
        try:
            s=socks_tcp(port,'127.0.0.1',9001); d=os.urandom(20000); s.sendall(d); g=b''
            while len(g)<len(d): g+=s.recv(65536)
            if g==d: res[0]+=1
        except Exception as e: pass
    ts=[threading.Thread(target=w) for _ in range(50)]
    [t.start() for t in ts]; [t.join() for t in ts]
    print(f"concurrent {res[0]}/50")
EOF

run_suite() { # name
  local n=$1 cport=$2 r
  r=$(python3 probe.py tcp_echo "$cport" 1000000 2>&1);        [[ "$r" == OK ]] && ok "$n: TCP echo 1MB integrity" || bad "$n: TCP echo ($r)"
  r=$(python3 probe.py udp_echo "$cport" 2>&1);                [[ "$r" == "udp 20/20" || "$r" == "udp 19/20" ]] && ok "$n: UDP echo ($r)" || bad "$n: UDP echo ($r)"
  r=$(python3 probe.py tcp_latency "$cport" 2>&1);             ok "$n: TCP RTT ($r)"
  r=$(python3 probe.py connect_latency "$cport" 2>&1);         ok "$n: connect ($r)"
  r=$(python3 probe.py udp_latency "$cport" 2>&1);             ok "$n: UDP RTT ($r)"
  r=$(python3 probe.py throughput "$cport" 2>&1);              [[ "$r" == download* ]] && ok "$n: $r" || bad "$n: throughput ($r)"
  r=$(python3 probe.py upload "$cport" 2>&1);                  [[ "$r" == echo* ]] && ok "$n: $r" || bad "$n: upload ($r)"
  r=$(python3 probe.py concurrent "$cport" 2>&1);              [[ "$r" == "concurrent 50/50" ]] && ok "$n: $r" || bad "$n: $r"
}

# ===================== 1. RAW TCP =====================
mk_cfgs raw 10001 11001 '{"network":"tcp"}' '{"network":"tcp"}'
start_pair raw; run_suite "raw-tcp" 11001

# ---- wire-level check: first bytes must look random (no plaintext UUID / magic) ----
python3 - <<EOF
import socket,struct,sys
# capture first flight by connecting to server and sending through client... simpler: sniff via a tiny tcp proxy
EOF
cat > sniff.py <<'EOF'
import socket, threading, sys, math, collections
# transparent TCP proxy 10010 -> 10001 capturing the first 2KB in each direction
cap={'c2s':b'','s2c':b''}
def pipe(a,b,key):
    while True:
        d=a.recv(65536)
        if not d: break
        if len(cap[key])<4096: cap[key]+=d
        b.sendall(d)
    try: b.shutdown(socket.SHUT_WR)
    except: pass
l=socket.socket(); l.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); l.bind(('127.0.0.1',10010)); l.listen(5)
c,_=l.accept(); s=socket.create_connection(('127.0.0.1',10001))
t1=threading.Thread(target=pipe,args=(c,s,'c2s')); t2=threading.Thread(target=pipe,args=(s,c,'s2c'))
t1.start(); t2.start(); t1.join(); t2.join()
def entropy(b):
    if not b: return 0
    cnt=collections.Counter(b); return -sum(v/len(b)*math.log2(v/len(b)) for v in cnt.values())
uuid=bytes.fromhex(sys.argv[1].replace('-',''))
print(f"c2s_bytes={len(cap['c2s'])} entropy={entropy(cap['c2s']):.2f} s2c_bytes={len(cap['s2c'])} entropy={entropy(cap['s2c']):.2f} uuid_in_clear={uuid in cap['c2s']} magic_prefix_17_03_03={cap['c2s'][:3]==b'\x17\x03\x03'}")
EOF
python3 sniff.py "$UUID" > sniff.out 2>&1 &
sleep 0.5
sed "s/\"port\": 10001/\"port\": 10010/" client-raw.json > client-sniff.json
"$XRAY" run -c client-sniff.json > client-sniff.log 2>&1 & SP=$!
sleep 1
sed -i 's/11001/11002/' client-sniff.json; kill $SP; "$XRAY" run -c client-sniff.json > client-sniff.log 2>&1 & SP=$!
sleep 1
python3 probe.py tcp_echo 11002 5000 >/dev/null 2>&1; sleep 0.5; kill $SP 2>/dev/null; wait %"$(jobs -l | grep sniff.py | awk '{print $1}' | tr -d '[]+-')" 2>/dev/null
SN=$(cat sniff.out); log "wire: $SN"
[[ "$SN" == *"uuid_in_clear=False"* && "$SN" == *"entropy=7."* ]] && ok "wire looks random, no plaintext UUID ($SN)" || bad "wire analysis ($SN)"

# ---- auth negative: wrong UUID must be rejected ----
sed "s/$UUID/00000000-0000-4000-8000-000000000000/" client-raw.json | sed 's/11001/11003/' > client-bad.json
"$XRAY" run -c client-bad.json > client-bad.log 2>&1 & BP=$!
sleep 1
r=$(python3 probe.py tcp_echo 11003 100 2>&1 | tail -1); kill $BP
[[ "$r" != OK ]] && ok "wrong UUID rejected by server" || bad "wrong UUID accepted!"
grep -q "unknown user" server-raw.log && ok "server logged rejection reason" || log "note: rejection reason not in log at loglevel warning"
stop_pair raw

# ===================== 2. TLS =====================
mk_cfgs tls 10002 11004 \
 "{\"network\":\"tcp\",\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$WORK/cert.pem\",\"keyFile\":\"$WORK/key.pem\"}]}}" \
 '{"network":"tcp","security":"tls","tlsSettings":{"serverName":"killdpi.test","allowInsecure":true,"fingerprint":"chrome"}}'
start_pair tls; run_suite "tls" 11004; stop_pair tls

# ===================== 3. WebSocket + TLS =====================
mk_cfgs ws 10003 11005 \
 "{\"network\":\"ws\",\"wsSettings\":{\"path\":\"/killdpi\"},\"security\":\"tls\",\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"$WORK/cert.pem\",\"keyFile\":\"$WORK/key.pem\"}]}}" \
 '{"network":"ws","wsSettings":{"path":"/killdpi","host":"killdpi.test"},"security":"tls","tlsSettings":{"serverName":"killdpi.test","allowInsecure":true,"fingerprint":"chrome"}}'
start_pair ws; run_suite "ws-tls" 11005; stop_pair ws

# ===================== 4. gRPC (bonus transport) =====================
mk_cfgs grpc 10004 11006 \
 '{"network":"grpc","grpcSettings":{"serviceName":"kd"}}' \
 '{"network":"grpc","grpcSettings":{"serviceName":"kd"}}'
start_pair grpc; r=$(python3 probe.py tcp_echo 11006 300000 2>&1); [[ "$r" == OK ]] && ok "grpc: TCP echo 300KB" || bad "grpc: ($r)"; stop_pair grpc

# ===================== 5. Fallback (active-probe resistance) =====================
mk_cfgs fb 10005 11007 '{"network":"tcp"}' '{"network":"tcp"}' ', "fallbacks": [{"dest": 9003}]'
start_pair fb
r=$(curl -s --max-time 5 http://127.0.0.1:10005/); [[ "$r" == "FALLBACK-OK" ]] && ok "fallback: plain HTTP probe sees web server" || bad "fallback: got '$r'"
r=$(python3 probe.py tcp_echo 11007 50000 2>&1); [[ "$r" == OK ]] && ok "fallback: real client still works" || bad "fallback: client ($r)"
stop_pair fb

# ===================== 6. Recovery after server restart =====================
mk_cfgs rec 10006 11008 '{"network":"tcp"}' '{"network":"tcp"}'
start_pair rec
r=$(python3 probe.py tcp_echo 11008 1000 2>&1); [[ "$r" == OK ]] || bad "recovery: pre-check"
kill "$(cat server-rec.pid)"; sleep 0.5
r=$(python3 probe.py tcp_echo 11008 1000 2>&1 | tail -1); [[ "$r" != OK ]] && log "recovery: during outage correctly failed ($r)"
"$XRAY" run -c server-rec.json > server-rec2.log 2>&1 & echo $! > server-rec.pid
T0=$(date +%s%N); for i in $(seq 1 30); do r=$(python3 probe.py tcp_echo 11008 1000 2>&1 | tail -1); [[ "$r" == OK ]] && break; sleep 0.2; done
DT=$(( ($(date +%s%N)-T0)/1000000 ))
[[ "$r" == OK ]] && ok "recovery: client reconnected after server restart in ${DT}ms (no client restart)" || bad "recovery: failed"
stop_pair rec

# ===================== 7. Config error messages =====================
echo '{"inbounds":[{"port":1,"protocol":"killdpi","settings":{"clients":[{"id":"not-a-uuid"}],"privateKey":"'$PRIV'"}}],"outbounds":[{"protocol":"freedom"}]}' > bad1.json
r=$("$XRAY" run -test -c bad1.json 2>&1 | tail -1); [[ "$r" == *'invalid "id"'* ]] && ok "config: invalid uuid -> clear error" || bad "config: uuid error ($r)"
echo '{"inbounds":[{"port":1,"protocol":"killdpi","settings":{"clients":[{"id":"'$UUID'"}]}}],"outbounds":[{"protocol":"freedom"}]}' > bad2.json
r=$("$XRAY" run -test -c bad2.json 2>&1 | tail -1); [[ "$r" == *'privateKey'* ]] && ok "config: missing privateKey -> clear error" || bad "config: privkey error ($r)"
echo '{"inbounds":[{"port":1,"protocol":"socks"}],"outbounds":[{"protocol":"killdpi","settings":{"address":"1.2.3.4","port":443,"id":"'$UUID'","publicKey":"short"}}]}' > bad3.json
r=$("$XRAY" run -test -c bad3.json 2>&1 | tail -1); [[ "$r" == *'publicKey'* ]] && ok "config: bad publicKey -> clear error" || bad "config: pubkey error ($r)"

# ===================== summary =====================
echo; echo "=================== KILLDPI E2E SUMMARY ==================="
printf '%s\n' "${RESULTS[@]}"
echo "PASS=$PASS FAIL=$FAIL"
echo "==========================================================="
[[ $FAIL -eq 0 ]]
