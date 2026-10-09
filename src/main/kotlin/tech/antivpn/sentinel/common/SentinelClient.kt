package tech.antivpn.sentinel.common

import com.google.gson.JsonParser
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap

/**
 * High-performance, non-blocking asynchronous HTTP client for the Sentinel Edge API.
 */
class SentinelClient(
    private val config: SentinelConfig,
    private val infoLogger: (String) -> Unit = {},
    private val errorLogger: (String) -> Unit = {}
) {
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
        .build()

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private var hasWarnedUnconfiguredKey = false

    private data class CacheEntry(
        val verdict: SentinelVerdict,
        val expiresAt: Long
    ) {
        val isValid: Boolean
            get() = System.currentTimeMillis() < expiresAt
    }

    @Volatile
    private var backoffUntil: Long = 0

    /**
     * Evaluates an IP address asynchronously.
     * Guaranteed fail-open: On timeout or network failure, returns an ALLOW verdict.
     */
    fun evaluate(ip: String?): CompletableFuture<SentinelVerdict> {
        if (ip.isNullOrBlank() || isLocalAddress(ip)) {
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(ip ?: "unknown"))
        }

        val normalizedIp = ip.trim()

        // Guard unconfigured / placeholder license keys
        if (config.licenseKey.isBlank() || config.licenseKey == "stl_live_your_api_key_here" || config.licenseKey == "stl_test_showcase_demo") {
            if (!hasWarnedUnconfiguredKey) {
                hasWarnedUnconfiguredKey = true
                errorLogger("[Sentinel] ⚠️ Protection paused (failing open): No active license key configured in config.yml. Claim your key at https://antivpn.tech")
            }
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }

        // 1. Check in-memory cache (checks direct IP and IPv6 /64 prefix to prevent rotation attacks)
        val subnetKey = getSubnetKey(normalizedIp)
        val cached = cache[normalizedIp] ?: cache[subnetKey]
        if (cached != null && cached.isValid) {
            return CompletableFuture.completedFuture(cached.verdict)
        }

        // Check if currently under HTTP 429 rate limit backoff
        val now = System.currentTimeMillis()
        if (now < backoffUntil) {
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }

        // 2. Query Sentinel Edge API
        return try {
            val encodedIp = URLEncoder.encode(normalizedIp, StandardCharsets.UTF_8)
            val url = "${config.endpoint}?ip=$encodedIp"

            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(config.timeoutMs.toLong()))
                .header("User-Agent", "Sentinel-Minecraft/1.0.0")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer ${config.licenseKey}")
                .header("X-Sentinel-Key", config.licenseKey)
                .GET()
                .build()

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply { response ->
                    val status = response.statusCode()

                    // Monitor Quota Remaining Header
                    val quotaRemainingOpt = response.headers().firstValue("X-Sentinel-Quota-Remaining")
                    if (quotaRemainingOpt.isPresent) {
                        val remaining = quotaRemainingOpt.get().toLongOrNull()
                        if (remaining != null && remaining in 1..499) {
                            errorLogger("[Sentinel] ⚠️ Monthly license quota running low: Only $remaining checks remaining in active billing cycle!")
                        }
                    }

                    if (status == 200) {
                        val verdict = parseVerdict(normalizedIp, response.body())
                        val ttlMs = config.cacheDurationMinutes.toLong() * 60 * 1000
                        val expiry = System.currentTimeMillis() + ttlMs

                        cache[normalizedIp] = CacheEntry(verdict, expiry)
                        if (normalizedIp.contains(":")) {
                            cache[subnetKey] = CacheEntry(verdict, expiry)
                        }
                        verdict
                    } else if (status == 429) {
                        val retryAfter = response.headers().firstValue("Retry-After").orElse("5").toLongOrNull() ?: 5L
                        backoffUntil = System.currentTimeMillis() + (retryAfter * 1000)
                        errorLogger("[Sentinel] ⚠️ Rate limit exceeded (HTTP 429). Backing off edge queries for ${retryAfter}s: ${response.body()}")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    } else if (status == 403) {
                        errorLogger("[Sentinel] 🚨 Edge API returned HTTP 403 (Quota Depleted or Forbidden): ${response.body()}. Failing open.")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    } else {
                        errorLogger("[Sentinel] Edge API returned HTTP $status for $normalizedIp: ${response.body()}")
                        SentinelVerdict.fallbackAllow(normalizedIp)
                    }
                }
                .exceptionally { ex ->
                    errorLogger("[Sentinel] Connection failure communicating with Sentinel Edge API: ${ex.message} (failing open)")
                    SentinelVerdict.fallbackAllow(normalizedIp)
                }
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct evaluation request for $normalizedIp: ${e.message}")
            CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(normalizedIp))
        }
    }

    /**
     * Canonicalizes IPv6 addresses to their /64 subnet prefix to prevent
     * rotating IPv6 bot swarm attacks from depleting license quota.
     */
    fun getSubnetKey(ip: String): String {
        if (!ip.contains(":")) return ip
        val parts = ip.split(":")
        if (parts.size >= 4) {
            return "${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}::/64"
        }
        return ip
    }

    private fun parseVerdict(ip: String, jsonBody: String): SentinelVerdict {
        return try {
            val root = JsonParser.parseString(jsonBody).asJsonObject

            val action = if (root.has("action") && !root.get("action").isJsonNull) root.get("action").asString else "ALLOW"
            val riskScore = if (root.has("risk_score") && !root.get("risk_score").isJsonNull) root.get("risk_score").asInt else 0
            val confidence = if (root.has("confidence") && !root.get("confidence").isJsonNull) root.get("confidence").asDouble else (if (action == "ALLOW") 0.99 else 0.90)
            val threatType = if (root.has("threat_type") && !root.get("threat_type").isJsonNull) root.get("threat_type").asString else "Clean Residential"
            val isVpn = root.has("is_vpn") && !root.get("is_vpn").isJsonNull && root.get("is_vpn").asBoolean
            val isGamingOptimizer = root.has("is_gaming_optimizer") && !root.get("is_gaming_optimizer").isJsonNull && root.get("is_gaming_optimizer").asBoolean
            val asn = if (root.has("asn") && !root.get("asn").isJsonNull) root.get("asn").asLong else 0L
            val provider = if (root.has("provider") && !root.get("provider").isJsonNull) root.get("provider").asString else "Unknown Provider"
            val hostname = if (root.has("hostname") && !root.get("hostname").isJsonNull) root.get("hostname").asString else null
            val country = if (root.has("country") && !root.get("country").isJsonNull) root.get("country").asString else "ZZ"
            val city = if (root.has("city") && !root.get("city").isJsonNull) root.get("city").asString else null
            val region = if (root.has("region") && !root.get("region").isJsonNull) root.get("region").asString else null
            val durationMs = when {
                root.has("execution_time_ms") && !root.get("execution_time_ms").isJsonNull -> root.get("execution_time_ms").asLong
                root.has("duration_ms") && !root.get("duration_ms").isJsonNull -> root.get("duration_ms").asLong
                else -> 0L
            }

            val reasonCodes = mutableListOf<String>()
            if (root.has("reason_codes") && root.get("reason_codes").isJsonArray) {
                val array = root.getAsJsonArray("reason_codes")
                for (elem in array) {
                    if (!elem.isJsonNull) {
                        reasonCodes.add(elem.asString)
                    }
                }
            } else if (root.has("reasons") && root.get("reasons").isJsonArray) {
                val array = root.getAsJsonArray("reasons")
                for (elem in array) {
                    if (!elem.isJsonNull) {
                        reasonCodes.add(elem.asString)
                    }
                }
            }

            SentinelVerdict(
                ip = ip,
                action = action,
                riskScore = riskScore,
                confidence = confidence,
                threatType = threatType,
                isVpn = isVpn,
                isGamingOptimizer = isGamingOptimizer,
                asn = asn,
                provider = provider,
                hostname = hostname,
                country = country,
                city = city,
                region = region,
                reasonCodes = reasonCodes,
                reasons = reasonCodes,
                durationMs = durationMs
            )
        } catch (e: Exception) {
            errorLogger("[Sentinel] Error parsing verdict payload: ${e.message} | Raw: $jsonBody")
            SentinelVerdict.fallbackAllow(ip)
        }
    }

    fun isCached(ip: String?): Boolean {
        if (ip.isNullOrBlank()) return false
        val entry = cache[ip.trim()]
        return entry != null && entry.isValid
    }

    fun clearCache() {
        cache.clear()
    }

    val cacheSize: Int
        get() = cache.size

    private fun isLocalAddress(ip: String): Boolean {
        return ip == "127.0.0.1" || ip == "0:0:0:0:0:0:0:1" || ip == "::1" ||
                ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") ||
                ip.startsWith("172.17.") || ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
                ip.startsWith("172.2") || ip.startsWith("172.30.") || ip.startsWith("172.31.")
    }
}
