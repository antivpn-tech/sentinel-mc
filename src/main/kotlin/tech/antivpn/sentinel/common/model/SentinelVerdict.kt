package tech.antivpn.sentinel.common.model

/**
 * Model representing a threat intelligence evaluation result from the Sentinel Edge API.
 */
data class SentinelVerdict(
    val ip: String = "unknown",
    val action: String = "ALLOW",
    val riskScore: Int = 0,
    val confidence: Double = 0.0,
    val threatType: String = "Clean Residential",
    val isVpn: Boolean = false,
    val isGamingOptimizer: Boolean = false,
    val asn: Long = 0,
    val provider: String = "Unknown Provider",
    val country: String = "ZZ",
    val city: String? = null,
    val region: String? = null,
    val reasonCodes: List<String> = emptyList(),
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
     * Identifies deterministic hard threats (Commercial VPNs, Datacenter VPS, Tor Exit Nodes,
     * or high-confidence explicit blocks) where an immediate hard kick is statistically safe.
     */
    fun isHardThreat(threshold: Int = 80, allowGamingOptimizers: Boolean = true): Boolean {
        if (allowGamingOptimizers && isGamingOptimizer) {
            return false
        }
        if (action.equals("BLOCK", ignoreCase = true)) {
            return true
        }
        if (reasonCodes.contains("CARRIER_COMMERCIAL_VPN") ||
            reasonCodes.contains("HOSTING_INFRASTRUCTURE_MATCH") ||
            reasonCodes.contains("TOR_EXIT_NODE")) {
            return true
        }
        // High confidence threshold check
        return isVpn && riskScore >= threshold && (confidence >= 0.85 || confidence == 0.0)
    }

    /**
     * Identifies probabilistic dynamic residential proxies or covert tunnel anomalies
     * where graduated defense (alerting, 2FA, rate limits) is recommended to prevent
     * false positive kicks against legitimate players.
     */
    fun isSuspectResidentialTunnel(): Boolean {
        return reasonCodes.contains("RESIDENTIAL_TUNNEL_PROXY") ||
               (threatType.contains("Residential", ignoreCase = true) && riskScore >= 65)
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
                confidence = 0.0,
                threatType = "Clean (Fallback)",
                isVpn = false,
                isGamingOptimizer = false,
                asn = 0,
                provider = "Fail-Open Fallback",
                country = "ZZ",
                city = null,
                region = null,
                reasonCodes = listOf("EDGE_API_TIMEOUT_FAIL_OPEN"),
                reasons = listOf("Edge API timeout or connection failure (fail-open allow)"),
                durationMs = 0
            )
        }
    }
}
