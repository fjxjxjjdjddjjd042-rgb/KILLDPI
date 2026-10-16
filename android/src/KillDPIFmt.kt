package com.v2ray.ang.fmt

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * KILLDPI share link:
 *   killdpi://<uuid>@<host>:<port>?pbk=<server-pubkey>&cipher=<c>&type=<tcp|ws|grpc>
 *            &security=<none|tls>&sni=..&host=..&path=..&fp=..&padding=min-max&keepalive=N&pcs=<sha256>#name
 *
 * Mapping onto ProfileItem (reusing existing columns, so no schema migration):
 *   password  = uuid
 *   publicKey = server X25519 public key (pbk)
 *   method    = cipher
 *   flow      = padding ("min-max")   -- VLESS flow column, unused by KILLDPI
 *   seed      = keepalive seconds     -- mKCP seed column, unused by KILLDPI
 */
object KillDPIFmt : FmtBase() {

    const val CIPHER_CHACHA = "chacha20-poly1305"
    const val CIPHER_AES = "aes-256-gcm"
    val CIPHERS = listOf(CIPHER_CHACHA, CIPHER_AES)
    private val UUID_RE = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    class ParseException(message: String) : IllegalArgumentException(message)

    fun parse(str: String): ProfileItem? {
        val config = ProfileItem.create(EConfigType.KILLDPI)
        val uri = URI(Utils.fixIllegalUrl(str))
        if (uri.rawQuery.isNullOrEmpty()) throw ParseException("KILLDPI: link has no parameters (pbk is required)")
        val q = getQueryParam(uri)

        val uuid = uri.userInfo.orEmpty()
        if (!UUID_RE.matches(uuid)) throw ParseException("KILLDPI: invalid UUID")
        val pbk = q["pbk"].orEmpty()
        if (pbk.length < 40) throw ParseException("KILLDPI: missing or invalid server public key (pbk)")
        val cipher = q["cipher"] ?: CIPHER_CHACHA
        if (cipher !in CIPHERS) throw ParseException("KILLDPI: unsupported cipher '$cipher'")
        if (uri.port <= 0) throw ParseException("KILLDPI: missing port")

        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).ifEmpty { "KILLDPI" }
        config.server = uri.idnHost
        config.serverPort = uri.port.toString()
        config.password = uuid
        config.method = cipher

        getItemFormQuery(config, q)
        config.publicKey = pbk
        config.flow = q["padding"]
        config.seed = q["keepalive"]
        val net = config.network ?: "tcp"
        if (net !in listOf("tcp", "ws", "grpc")) throw ParseException("KILLDPI: transport '$net' not supported (tcp/ws/grpc)")
        return config
    }

    fun toUri(config: ProfileItem): String {
        val dic = getQueryDic(config)
        dic.remove("flow")
        dic["pbk"] = config.publicKey.orEmpty()
        dic["cipher"] = config.method ?: CIPHER_CHACHA
        config.flow?.nullIfBlank()?.let { dic["padding"] = it }
        config.seed?.nullIfBlank()?.let { dic["keepalive"] = it }
        return toUri(config, config.password, dic)
    }
}
