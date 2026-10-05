package tech.antivpn.sentinel.common.model

/**
 * Model representing a threat intelligence evaluation result from the Sentinel Edge API.
 */
data class SentinelVerdict(
    val ip: String = "unknown",
    val action: String = "ALLOW",
    val riskScore: Int = 0,
    val threatType: String = "Clean Residential",
    val isVpn: Boolean = false,
    val isGamingOptimizer: Boolean = false,
    val asn: Long = 0,
    val provider: String = "Unknown Provider",
    val country: String = "ZZ",
    val city: String? = null,
    val region: String? = null,
    val reasons: List<String> = emptyList(),
    val durationMs: Long = 0
) {
    /**
     * Determines whether this connection is classified as a threat given the threshold
     * and gaming optimizer whitelist settings.
     */
    fun isThreat(threshold: Int, allowGamingOptimizers: Boolean): Boolean {
        if (allowGamingOptimizers && isGamingOptimizer) {
            return false
        }
        return action.equals("BLOCK", ignoreCase = true) || riskScore >= threshold || isVpn
    }

    /**
     * Formats geo-location details into a readable string (e.g., "Dallas, TX, US").
     */
    fun getFormattedLocation(): String {
        val parts = mutableListOf<String>()
        city?.takeIf { it.isNotBlank() }?.let { parts.add(it) }
        region?.takeIf { it.isNotBlank() }?.let { parts.add(it) }
        parts.add(country)
        return parts.joinToString(", ")
    }

    companion object {
        @JvmStatic
        fun fallbackAllow(ip: String): SentinelVerdict {
            return SentinelVerdict(
                ip = ip,
                action = "ALLOW",
                riskScore = 0,
                threatType = "Clean (Fallback)",
                isVpn = false,
                isGamingOptimizer = false,
                asn = 0,
                provider = "Fail-Open Fallback",
                country = "ZZ",
                city = null,
                region = null,
                reasons = listOf("Edge API timeout or connection failure (fail-open allow)"),
                durationMs = 0
            )
        }
    }
}
