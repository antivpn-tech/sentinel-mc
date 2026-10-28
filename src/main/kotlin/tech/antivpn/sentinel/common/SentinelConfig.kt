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
    val graduatedDefense: Boolean = true,
    val cacheDurationMinutes: Int = 30,
    val discordEnabled: Boolean = true,
    val discordWebhookUrl: String = "",
    val discordNotifyOnlyOnThreat: Boolean = true,
    val discordServerName: String = "Minecraft Network",
    val kickMessage: String = "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."
) {
    val isAuditMode: Boolean
        get() = mode.equals("AUDIT", ignoreCase = true)

    val isDiscordConfigured: Boolean
        get() = discordEnabled && discordWebhookUrl.isNotBlank()

    companion object {
        const val FORCED_KICK_HEADER = "&9&lSentinel Protection"

        @JvmStatic
        fun createDefault(): SentinelConfig = SentinelConfig()

        /**
         * Normalizes newline escape sequences (\r\n, literal \n, /n, /N) to standard LF (\n),
         * protecting embedded URLs so links (e.g. Discord or web URLs) remain intact.
         */
        @JvmStatic
        fun normalizeNewlines(input: String): String {
            if (input.isEmpty()) return input

            // Protect URLs and discord invite links from /n replacement
            val urlRegex = Regex("""(?:https?://|www\.|discord\.gg/)[^\s)\]">]+""", RegexOption.IGNORE_CASE)
            val urls = mutableListOf<String>()
            val placeholderPrefix = "___SENTINEL_URL_"
            val placeholderSuffix = "___"

            val masked = urlRegex.replace(input) { match ->
                val idx = urls.size
                urls.add(match.value)
                "$placeholderPrefix$idx$placeholderSuffix"
            }

            var result = masked
                .replace("\r\n", "\n")
                .replace("\\r\\n", "\n")
                .replace("\\n", "\n")
                .replace("\\/n", "\n")
                .replace(Regex("""(?i)/n"""), "\n")

            for ((idx, url) in urls.withIndex()) {
                result = result.replace("$placeholderPrefix$idx$placeholderSuffix", url)
            }

            return result
        }
    }

    /**
     * Builds the complete enforcement kick message.
     * Forces the blue bold header (&9&lSentinel Protection) as the unremovable first line,
     * normalizes line breaks (\n and /n), and strips any redundant legacy headers from older configs.
     */
    fun buildEnforcementKickMessage(
        threat: String = "",
        risk: Int = 0,
        ip: String = "",
        player: String = ""
    ): String {
        var body = kickMessage
            .replace("%threat%", threat)
            .replace("%risk%", risk.toString())
            .replace("%ip%", ip)
            .replace("%player%", player)

        body = normalizeNewlines(body).trim()

        // Strip legacy or redundant Sentinel Protection headers from upgraded configs
        val legacyHeaderRegex = Regex(
            """^(?:&[0-9a-fk-orA-FK-OR§]|\[|\s)*Sentinel Protection(?:\])?(?:\s*[:\-])?\s*(?:\n|\Z)""",
            RegexOption.IGNORE_CASE
        )
        body = legacyHeaderRegex.replace(body, "").trimStart('\n', '\r', ' ')

        return if (body.isEmpty()) {
            FORCED_KICK_HEADER
        } else {
            val formattedBody = if (body.startsWith("&") || body.startsWith("§")) body else "&r$body"
            "$FORCED_KICK_HEADER\n$formattedBody"
        }
    }
}
