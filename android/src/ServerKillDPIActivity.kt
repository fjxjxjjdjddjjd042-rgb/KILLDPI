package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.fmt.KillDPIFmt
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField

class ServerKillDPIActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.KILLDPI

    @Composable
    override fun ScreenContent() {
        val options = rememberFieldOptions()
        val scope = rememberCoroutineScope()
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply { configType = EConfigType.KILLDPI }

        ServerEditorScaffold(title = "KILLDPI", onSaveClick = { saveServer(uiState) }) {
            CommonBasicFields(uiState)
            FormTextField(
                label = stringResource(R.string.server_lab_id),
                value = uiState.password,
                onValueChange = { uiState.password = it },
                isError = uiState.isPasswordError
            )
            FormTextField(
                label = stringResource(R.string.server_lab_killdpi_pbk),
                value = uiState.publicKey,
                onValueChange = { uiState.publicKey = it }
            )
            FormDropdownField(
                stringResource(R.string.server_lab_killdpi_cipher),
                uiState.method.ifEmpty { KillDPIFmt.CIPHER_CHACHA },
                KillDPIFmt.CIPHERS,
                { uiState.method = it }
            )
            FormTextField(
                label = stringResource(R.string.server_lab_killdpi_padding),
                value = uiState.flow,
                onValueChange = { uiState.flow = it }
            )
            CommonNetworkFields(uiState, options)
            CommonStreamSecurityFields(
                state = uiState, options = options, scope = scope,
                buildProfileItem = { uiState.toProfileItem(initialConfig) }
            )
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean =
        !config.password.isNullOrBlank() && (config.publicKey?.length ?: 0) >= 40
}
