package tech.antivpn.sentinel.common

/**
 * Immutable configuration options for the Sentinel protection engine.
 */
data class SentinelConfig(
    val endpoint: String = "https://api.antivpn.tech/v1/check",
    val licenseKey: String = "stl_live_your_api_key_here",
    val timeoutMs: Int = 2500,
    val mode: String = "ENFORCE",
    val riskThreshold: Int = 80,
    val allowGamingOptimizers: Boolean = true,
    val cacheDurationMinutes: Int = 30,
    val discordEnabled: Boolean = true,
    val discordWebhookUrl: String = "",
    val discordNotifyOnlyOnThreat: Boolean = true,
    val discordServerName: String = "Minecraft Network",
    val kickMessage: String = "&c&lSentinel Protection\n&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100",
    val antiBotEnabled: Boolean = true,
    val antiBotBurstThreshold: Int = 5,
    val antiBotShieldDurationSeconds: Int = 15,
    val antiBotQuarantineSeconds: Int = 60,
    val antiBotKickMessage: String = "&c&lSentinel Gate\n&7Gate active due to abnormal connection velocity.\n&7Please reconnect in a few seconds."
) {
    val isAuditMode: Boolean
        get() = mode.equals("AUDIT", ignoreCase = true)

    val isDiscordConfigured: Boolean
        get() = discordEnabled && discordWebhookUrl.isNotBlank()

    companion object {
        @JvmStatic
        fun createDefault(): SentinelConfig = SentinelConfig()
    }
}
