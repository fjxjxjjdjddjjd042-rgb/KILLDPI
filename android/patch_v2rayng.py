#!/usr/bin/env python3
"""Apply KILLDPI integration to a fresh v2rayNG checkout.

Usage: python3 patch_v2rayng.py <path-to-v2rayNG-repo-root>

Idempotent: every edit checks whether it was already applied. Fails loudly if
an anchor cannot be found (upstream refactor) so CI never ships a half patch.
"""
from __future__ import annotations

import os
import shutil
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "v2rayNG"
APP = os.path.join(ROOT, "V2rayNG", "app", "src", "main")
J = os.path.join(APP, "java", "com", "v2ray", "ang")
HERE = os.path.dirname(os.path.abspath(__file__))
changed: list[str] = []


def read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def write(p: str, s: str) -> None:
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)
    changed.append(os.path.relpath(p, ROOT))


def edit(path: str, anchor: str, new: str, *, after: bool = True, marker: str | None = None) -> None:
    s = read(path)
    if (marker or new.strip()) in s:
        return
    if anchor not in s:
        sys.exit(f"ANCHOR NOT FOUND in {path}:\n{anchor}")
    write(path, s.replace(anchor, anchor + new if after else new + anchor, 1))


def replace(path: str, old: str, new: str) -> None:
    s = read(path)
    if new in s:
        return
    if old not in s:
        sys.exit(f"TEXT NOT FOUND in {path}:\n{old}")
    write(path, s.replace(old, new, 1))


# 1. new source files
for src, dst in (("KillDPIFmt.kt", os.path.join(J, "fmt", "KillDPIFmt.kt")),
                 ("ServerKillDPIActivity.kt", os.path.join(J, "ui", "server", "ServerKillDPIActivity.kt"))):
    s = os.path.join(HERE, "src", src)
    if not os.path.exists(dst) or read(dst) != read(s):
        shutil.copy(s, dst)
        changed.append(os.path.relpath(dst, ROOT))

# 2. AppConfig scheme constant
edit(os.path.join(J, "AppConfig.kt"), '    const val VLESS = "vless://"\n', '    const val KILLDPI = "killdpi://"\n')

# 3. EConfigType (value 11 unused upstream)
edit(os.path.join(J, "enums", "EConfigType.kt"), "    HTTP(10, AppConfig.HTTP),\n", "    KILLDPI(11, AppConfig.KILLDPI),\n")

# 4. Import / share
p = os.path.join(J, "handler", "AngConfigManager.kt")
edit(p, "            EConfigType.VLESS.protocolScheme to VlessFmt::parse,\n",
     "            EConfigType.KILLDPI.protocolScheme to KillDPIFmt::parse,\n")
edit(p, "                EConfigType.VLESS -> VlessFmt.toUri(config)\n", "                EConfigType.KILLDPI -> KillDPIFmt.toUri(config)\n")
edit(p, "import com.v2ray.ang.fmt.VlessFmt\n", "import com.v2ray.ang.fmt.KillDPIFmt\n")

# 5. Outbound builder
p = os.path.join(J, "core", "CoreOutboundBuilder.kt")
edit(p, "            EConfigType.VLESS -> toOutboundVless(profileItem)\n", "            EConfigType.KILLDPI -> toOutboundKillDPI(profileItem)\n")
edit(p, "            EConfigType.VMESS,\n            EConfigType.VLESS,\n", "            EConfigType.KILLDPI,\n",
     marker="            EConfigType.KILLDPI,\n            EConfigType.SHADOWSOCKS,")
edit(p, "    private fun toOutboundVless(profileItem: ProfileItem): OutboundBean? {\n",
     '''    /** KILLDPI outbound: address/port/id + server publicKey + cipher (+ optional padding/keepalive). */
    private fun toOutboundKillDPI(profileItem: ProfileItem): OutboundBean? {
        val outboundBean = createInitOutbound(EConfigType.KILLDPI)

        outboundBean?.settings?.let { settings ->
            settings.address = getServerAddress(profileItem)
            settings.port = profileItem.serverPort.orEmpty().toInt()
            settings.id = profileItem.password.orEmpty()
            settings.publicKey = profileItem.publicKey.orEmpty()
            settings.cipher = profileItem.method ?: "chacha20-poly1305"
            settings.padding = profileItem.flow?.takeIf { it.isNotBlank() }
            settings.keepalive = profileItem.seed?.toIntOrNull()
            settings.level = AppConfig.DEFAULT_LEVEL
        }

        val sni = outboundBean?.streamSettings?.let {
            populateTransportSettings(it, profileItem)
        }

        outboundBean?.streamSettings?.let {
            populateTlsSettings(it, profileItem, sni)
        }

        return outboundBean
    }

''', after=False, marker="toOutboundKillDPI(profileItem: ProfileItem)")

# 6. DTO fields
edit(os.path.join(J, "dto", "V2rayConfig.kt"), "            /*VLESS*/\n            var flow: String? = null,\n",
     "            /*KILLDPI*/\n            var publicKey: String? = null,\n            var cipher: String? = null,\n"
     "            var padding: String? = null,\n            var keepalive: Int? = null,\n")

# 7. UI routing
edit(os.path.join(J, "ui", "main", "MainImportMenu.kt"),
     "    Vless(R.string.menu_item_import_config_manually_vless, MainAction.ImportManually(EConfigType.VLESS.value)),\n",
     "    KillDPI(R.string.menu_item_import_config_manually_killdpi, MainAction.ImportManually(EConfigType.KILLDPI.value)),\n")
p = os.path.join(J, "ui", "main", "MainActivity.kt")
edit(p, "            EConfigType.VLESS.value -> Intent(this, ServerVlessActivity::class.java)\n",
     "            EConfigType.KILLDPI.value -> Intent(this, ServerKillDPIActivity::class.java)\n")
edit(p, "            EConfigType.VLESS -> ServerVlessActivity::class.java\n", "            EConfigType.KILLDPI -> ServerKillDPIActivity::class.java\n")
edit(p, "import com.v2ray.ang.ui.server.ServerVlessActivity\n", "import com.v2ray.ang.ui.server.ServerKillDPIActivity\n")

# 8. ServerUiState
p = os.path.join(J, "ui", "server", "ServerUiState.kt")
edit(p, "        val isVless = configType == EConfigType.VLESS\n", "        val isKillDPI = configType == EConfigType.KILLDPI\n")
replace(p, "                isVless -> encryption\n                else -> null\n            },\n            flow = if (isVless) flow else null,",
        "                isVless -> encryption\n                isKillDPI -> method\n                else -> null\n            },\n            flow = if (isVless || isKillDPI) flow else null,")
replace(p, "            publicKey = when {\n                isWireguard -> publicKey\n",
        "            publicKey = when {\n                isWireguard || isKillDPI -> publicKey\n")

# 9. mandatory id
replace(os.path.join(J, "ui", "server", "BaseServerActivity.kt"),
        "            if (config.configType == EConfigType.VMESS ||\n                config.configType == EConfigType.VLESS\n            ) {",
        "            if (config.configType == EConfigType.VMESS ||\n                config.configType == EConfigType.VLESS ||\n                config.configType == EConfigType.KILLDPI\n            ) {")

# 10. manifest + strings
edit(os.path.join(APP, "AndroidManifest.xml"),
     '            android:name=".ui.server.ServerVlessActivity"\n            android:exported="false"\n'
     '            android:windowSoftInputMode="stateUnchanged|adjustResize" />\n',
     '        <activity\n            android:name=".ui.server.ServerKillDPIActivity"\n            android:exported="false"\n'
     '            android:windowSoftInputMode="stateUnchanged|adjustResize" />\n')
sp = os.path.join(APP, "res", "values", "strings.xml")
edit(sp, '    <string name="menu_item_import_config_manually_vless">Add [VLESS]</string>\n',
     '    <string name="menu_item_import_config_manually_killdpi">Add [KILLDPI]</string>\n'
     '    <string name="server_lab_killdpi_pbk">Server public key (pbk)</string>\n'
     '    <string name="server_lab_killdpi_cipher">Cipher</string>\n'
     '    <string name="server_lab_killdpi_padding">Handshake padding (min-max)</string>\n')

# 11. side-by-side install: new id + name
replace(os.path.join(ROOT, "V2rayNG", "app", "build.gradle.kts"), 'applicationId = "com.v2ray.ang"', 'applicationId = "com.killdpi.ng"')
s = read(sp)
if '<string name="app_name">v2rayNG</string>' in s:
    write(sp, s.replace('<string name="app_name">v2rayNG</string>', '<string name="app_name">KILLDPI</string>'))

print("patched files:")
for c in sorted(set(changed)):
    print("  ", c)
print("OK" if changed else "already patched")
