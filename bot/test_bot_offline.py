"""Offline tests: link format, profiles, storage, subscription stability. No network needed."""
import base64, json, os, shutil, sys, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from killdpi_link import KillDPIConfig, LinkError, server_inbound_json
from profiles import PROFILES, PROFILE_ORDER
from storage import LocalStorage

PBK = "SsRefZP5HZif8QcvncmOHqw23zTrBrjbnPcDYjBzsy0"

def test_link_roundtrip_all_profiles():
    for k in PROFILE_ORDER:
        p = PROFILES[k]
        c = KillDPIConfig(uuid=str(uuid.uuid4()), host="cdn.example.com" if p.use_cdn else "1.2.3.4", port=443,
                          pbk=PBK, cipher=p.cipher, network=p.network, security=p.security, sni="x.example.com",
                          ws_host="cdn.example.com" if p.network == "ws" else "", path="/killdpi" if p.network == "ws" else "", padding=p.padding, keepalive=p.keepalive, name=p.title)
        link = c.to_link()
        assert KillDPIConfig.from_link(link) == c, k
        ob = json.loads(c.to_client_json())["outbounds"][0]
        assert ob["protocol"] == "killdpi" and ob["settings"]["publicKey"] == PBK
        assert ob["streamSettings"]["network"] == p.network
    print("ok  link roundtrip for", len(PROFILE_ORDER), "profiles")

def test_bad_links():
    u = uuid.uuid4()
    bad = ["vless://a@b:1", f"killdpi://not-uuid@h:1?pbk={PBK}", f"killdpi://{u}@h:1",
           f"killdpi://{u}@h:1?pbk=short", f"killdpi://{u}@h:1?pbk={PBK}&cipher=rc4", f"killdpi://{u}@h:1?pbk={PBK}&type=kcp"]
    for b in bad:
        try:
            KillDPIConfig.from_link(b); raise AssertionError("accepted: " + b)
        except LinkError:
            pass
    print("ok  rejected", len(bad), "malformed links with readable errors")

def test_storage_and_stable_sub():
    shutil.rmtree("data_local", ignore_errors=True)
    st = LocalStorage()
    tok = st.new_token()
    u1 = st.publish_subscription(tok, ["killdpi://a"], "m")
    u2 = st.publish_subscription(tok, ["killdpi://a", "killdpi://b"], "m")
    assert u1 == u2, "subscription URL must be stable"
    body = open(f"data_local/subs/{tok}.txt").read().strip()
    assert base64.b64decode(body).decode().split("\n") == ["killdpi://a", "killdpi://b"]
    state = {"users": {"1": {"configs": []}}, "servers": [], "configs": {}}
    st.save_state(state); assert st.load_state() == state
    shutil.rmtree("data_local", ignore_errors=True)
    print("ok  storage + stable subscription URL")

def test_server_json():
    js = json.loads(server_inbound_json("priv", [{"id": str(uuid.uuid4())}], 443, "ws", fallback_port=8080))
    ib = js["inbounds"][0]
    assert ib["protocol"] == "killdpi" and ib["settings"]["fallbacks"][0]["dest"] == 8080
    print("ok  server json")

if __name__ == "__main__":
    test_link_roundtrip_all_profiles(); test_bad_links(); test_storage_and_stable_sub(); test_server_json()
    print("ALL BOT OFFLINE TESTS PASSED")
