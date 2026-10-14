package tech.antivpn.sentinel.common

import com.google.gson.JsonArray
import com.google.gson.JsonObject
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
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, non-blocking asynchronous HTTP client for the Sentinel Edge API.
 * Supports single-IP checks, automatic join-wave micro-batching (/v1/batch), and in-flight coalescing.
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
    private val inFlight = ConcurrentHashMap<String, CompletableFuture<SentinelVerdict>>()
    private val activeRequests = AtomicInteger(0)
    private val waveQueue = ConcurrentLinkedQueue<PendingCheck>()
    private val waveScheduled = AtomicBoolean(false)
    private val batchScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "Sentinel-JoinWave-Batcher").apply { isDaemon = true }
    }
    private var hasWarnedUnconfiguredKey = false

    private data class PendingCheck(
        val ip: String,
        val future: CompletableFuture<SentinelVerdict>
    )

    private data class CacheEntry(
        val verdict: SentinelVerdict,
        val expiresAt: Long
    ) {
        val isValid: Boolean
            get() = System.currentTimeMillis() < expiresAt
    }

    @Volatile
    private var backoffUntil: Long = 0

    companion object {
        private const val MAX_BATCH_SIZE = 20
        private const val JOIN_WAVE_WINDOW_MS = 15L
    }

    /**
     * Evaluates an IP address asynchronously.
     * Guaranteed fail-open: On timeout or network failure, returns an ALLOW verdict.
     * Automatically coalesces duplicate in-flight checks and batches concurrent join waves via /v1/batch.
     */
    fun evaluate(ip: String?): CompletableFuture<SentinelVerdict> {
        if (ip.isNullOrBlank() || isLocalAddress(ip)) {
            return CompletableFuture.completedFuture(SentinelVerdict.fallbackAllow(ip ?: "unknown"))
        }

        val normalizedIp = ip.trim()

        // Guard unconfigured / placeholder license keys
        if (isKeyUnconfigured()) {
            warnUnconfiguredKeyOnce()
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

        // 2. Coalesce identical concurrent in-flight requests (same IP or /64 IPv6 subnet)
        val existingInFlight = inFlight[normalizedIp] ?: inFlight[subnetKey]
        if (existingInFlight != null) {
            return existingInFlight
        }

        val resultFuture = CompletableFuture<SentinelVerdict>()
        val previous = inFlight.putIfAbsent(normalizedIp, resultFuture)
        if (previous != null) {
            return previous
        }
        resultFuture.whenComplete { _, _ ->
            inFlight.remove(normalizedIp, resultFuture)
        }

        // 3. If another edge check is already in-flight, coalesce this join into a micro-batch wave (/v1/batch)
        if (activeRequests.get() > 0) {
            enqueueWaveCheck(normalizedIp, resultFuture)
            return resultFuture
        }

        // 4. First check in an idle window fires immediately (zero artificial latency)
        activeRequests.incrementAndGet()
        sendSingleCheck(normalizedIp).whenComplete { verdict, ex ->
            activeRequests.decrementAndGet()
            if (ex != null) {
                resultFuture.complete(SentinelVerdict.fallbackAllow(normalizedIp))
            } else {
                resultFuture.complete(verdict ?: SentinelVerdict.fallbackAllow(normalizedIp))
            }
        }
        return resultFuture
    }

    private fun enqueueWaveCheck(ip: String, future: CompletableFuture<SentinelVerdict>) {
        waveQueue.add(PendingCheck(ip, future))
        if (waveQueue.size >= MAX_BATCH_SIZE) {
            flushWaveQueue()
            return
        }
        if (waveScheduled.compareAndSet(false, true)) {
            batchScheduler.schedule({
                waveScheduled.set(false)
                flushWaveQueue()
            }, JOIN_WAVE_WINDOW_MS, TimeUnit.MILLISECONDS)
        }
    }

    private fun flushWaveQueue() {
        val batch = mutableListOf<PendingCheck>()
        while (batch.size < MAX_BATCH_SIZE) {
            val next = waveQueue.poll() ?: break
            batch.add(next)
        }
        if (batch.isEmpty()) return

        // If more remain in the queue, flush the next chunk immediately
        if (waveQueue.isNotEmpty()) {
            batchScheduler.execute { flushWaveQueue() }
        }

        if (batch.size == 1) {
            val single = batch[0]
            activeRequests.incrementAndGet()
            sendSingleCheck(single.ip).whenComplete { verdict, ex ->
                activeRequests.decrementAndGet()
                single.future.complete(if (ex == null && verdict != null) verdict else SentinelVerdict.fallbackAllow(single.ip))
            }
            return
        }

        val ips = batch.map { it.ip }
        activeRequests.incrementAndGet()
        sendBatchChunk(ips).whenComplete { verdictMap, ex ->
            activeRequests.decrementAndGet()
            for (item in batch) {
                val verdict = if (ex == null && verdictMap != null) {
                    verdictMap[item.ip] ?: SentinelVerdict.fallbackAllow(item.ip)
                } else {
                    SentinelVerdict.fallbackAllow(item.ip)
                }
                item.future.complete(verdict)
            }
        }
    }

    /**
     * Evaluates a batch of IP addresses concurrently using POST /v1/batch.
     * Automatically serves cached/local IPs from memory and chunks uncached IPs into groups of 20.
     * Guaranteed fail-open on timeout or network failure.
     */
    fun evaluateBatch(ips: List<String>): CompletableFuture<Map<String, SentinelVerdict>> {
        if (ips.isEmpty()) {
            return CompletableFuture.completedFuture(emptyMap())
        }

        val results = ConcurrentHashMap<String, SentinelVerdict>()
        val uncached = LinkedHashSet<String>()
        val now = System.currentTimeMillis()
        val keyUnconfigured = isKeyUnconfigured()
        if (keyUnconfigured) {
            warnUnconfiguredKeyOnce()
        }

        for (rawIp in ips) {
            val trimmed = rawIp.trim()
            if (trimmed.isEmpty()) continue

            if (isLocalAddress(trimmed) || keyUnconfigured || now < backoffUntil) {
                results[trimmed] = SentinelVerdict.fallbackAllow(trimmed)
                continue
            }

            val subnetKey = getSubnetKey(trimmed)
            val cached = cache[trimmed] ?: cache[subnetKey]
            if (cached != null && cached.isValid) {
                results[trimmed] = cached.verdict
            } else {
                uncached.add(trimmed)
            }
        }

        if (uncached.isEmpty()) {
            return CompletableFuture.completedFuture(results)
        }

        val chunks = uncached.chunked(MAX_BATCH_SIZE)
        val chunkFutures = chunks.map { chunk ->
            sendBatchChunk(chunk).thenAccept { chunkMap ->
                results.putAll(chunkMap)
            }
        }

        return CompletableFuture.allOf(*chunkFutures.toTypedArray())
            .thenApply {
                for (rawIp in ips) {
                    val trimmed = rawIp.trim()
                    if (trimmed.isNotEmpty() && !results.containsKey(trimmed)) {
                        results[trimmed] = SentinelVerdict.fallbackAllow(trimmed)
                    }
                }
                results.toMap()
            }
            .exceptionally {
                for (rawIp in ips) {
                    val trimmed = rawIp.trim()
                    if (trimmed.isNotEmpty() && !results.containsKey(trimmed)) {
                        results[trimmed] = SentinelVerdict.fallbackAllow(trimmed)
                    }
                }
                results.toMap()
            }
    }

    private fun sendSingleCheck(normalizedIp: String): CompletableFuture<SentinelVerdict> {
        return try {
            val encodedIp = URLEncoder.encode(normalizedIp, StandardCharsets.UTF_8)
            val url = "${config.endpoint}?ip=$encodedIp"

            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(config.timeoutMs.toLong()))
                .header("User-Agent", "Sentinel-Minecraft/1.2.0")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer ${config.licenseKey}")
                .header("X-Sentinel-Key", config.licenseKey)
                .GET()
                .build()

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply { response ->
                    val status = response.statusCode()
                    monitorQuotaHeader(response)

                    if (status == 200) {
                        val verdict = parseVerdict(normalizedIp, response.body())
                        cacheVerdict(normalizedIp, verdict)
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

    private fun sendBatchChunk(chunk: List<String>): CompletableFuture<Map<String, SentinelVerdict>> {
        if (chunk.isEmpty()) {
            return CompletableFuture.completedFuture(emptyMap())
        }
        return try {
            val batchUrl = resolveBatchEndpoint(config.endpoint)
            val payload = JsonObject().apply {
                val arr = JsonArray()
                chunk.forEach { arr.add(it) }
                add("ips", arr)
            }.toString()

            val request = HttpRequest.newBuilder()
                .uri(URI.create(batchUrl))
                .timeout(Duration.ofMillis(config.timeoutMs.toLong()))
                .header("User-Agent", "Sentinel-Minecraft/1.2.0")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer ${config.licenseKey}")
                .header("X-Sentinel-Key", config.licenseKey)
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build()

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply { response ->
                    val status = response.statusCode()
                    monitorQuotaHeader(response)

                    if (status == 200) {
                        val verdicts = parseBatchVerdicts(chunk, response.body())
                        verdicts.forEach { (ip, verdict) -> cacheVerdict(ip, verdict) }
                        verdicts
                    } else if (status == 429) {
                        val retryAfter = response.headers().firstValue("Retry-After").orElse("5").toLongOrNull() ?: 5L
                        backoffUntil = System.currentTimeMillis() + (retryAfter * 1000)
                        errorLogger("[Sentinel] ⚠️ Batch rate limit exceeded (HTTP 429). Backing off edge queries for ${retryAfter}s.")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    } else if (status == 403) {
                        errorLogger("[Sentinel] 🚨 Edge API returned HTTP 403 on batch check: ${response.body()}. Failing open.")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    } else {
                        errorLogger("[Sentinel] Edge API returned HTTP $status for batch check (${chunk.size} IPs): ${response.body()}")
                        chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                    }
                }
                .exceptionally { ex ->
                    errorLogger("[Sentinel] Batch connection failure communicating with Sentinel Edge API: ${ex.message} (failing open)")
                    chunk.associateWith { SentinelVerdict.fallbackAllow(it) }
                }
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct batch evaluation request: ${e.message}")
            CompletableFuture.completedFuture(chunk.associateWith { SentinelVerdict.fallbackAllow(it) })
        }
    }

    private fun monitorQuotaHeader(response: HttpResponse<*>) {
        val quotaRemainingOpt = response.headers().firstValue("X-Sentinel-Quota-Remaining")
        if (quotaRemainingOpt.isPresent) {
            val remaining = quotaRemainingOpt.get().toLongOrNull()
            if (remaining != null && remaining in 1..499) {
                errorLogger("[Sentinel] ⚠️ Monthly license quota running low: Only $remaining checks remaining in active billing cycle!")
            }
        }
    }

    private fun cacheVerdict(ip: String, verdict: SentinelVerdict) {
        val ttlMs = config.cacheDurationMinutes.toLong() * 60 * 1000
        val expiry = System.currentTimeMillis() + ttlMs
        cache[ip] = CacheEntry(verdict, expiry)
        if (ip.contains(":")) {
            cache[getSubnetKey(ip)] = CacheEntry(verdict, expiry)
        }
    }

    private fun isKeyUnconfigured(): Boolean {
        return config.licenseKey.isBlank() ||
                config.licenseKey == "stl_live_your_api_key_here" ||
                config.licenseKey == "stl_test_showcase_demo"
    }

    private fun warnUnconfiguredKeyOnce() {
        if (!hasWarnedUnconfiguredKey) {
            hasWarnedUnconfiguredKey = true
            errorLogger("[Sentinel] ⚠️ Protection paused (failing open): No active license key configured in config.yml. Claim your key at https://antivpn.tech")
        }
    }

    internal fun resolveBatchEndpoint(endpoint: String): String {
        val trimmed = endpoint.trim()
        return when {
            trimmed.endsWith("/v1/check") -> trimmed.removeSuffix("/v1/check") + "/v1/batch"
            trimmed.endsWith("/api/check") -> trimmed.removeSuffix("/api/check") + "/api/batch"
            trimmed.endsWith("/check") -> trimmed.removeSuffix("/check") + "/batch"
            trimmed.endsWith("/v1/batch") || trimmed.endsWith("/api/batch") -> trimmed
            else -> trimmed.trimEnd('/') + "/v1/batch"
        }
    }

    internal fun parseBatchVerdicts(requestedIps: List<String>, jsonBody: String): Map<String, SentinelVerdict> {
        val out = LinkedHashMap<String, SentinelVerdict>()
        try {
            val root = JsonParser.parseString(jsonBody).asJsonObject
            if (root.has("results") && root.get("results").isJsonArray) {
                val resultsArray = root.getAsJsonArray("results")
                for (i in 0 until resultsArray.size()) {
                    val elem = resultsArray.get(i)
                    if (elem != null && elem.isJsonObject) {
                        val obj = elem.asJsonObject
                        val fallbackIp = requestedIps.getOrNull(i) ?: "unknown"
                        val itemIp = if (obj.has("ip") && !obj.get("ip").isJsonNull) obj.get("ip").asString else fallbackIp
                        val verdict = parseVerdict(itemIp, obj.toString())
                        out[itemIp] = verdict
                        if (i < requestedIps.size) {
                            out[requestedIps[i]] = verdict
                        }
                    }
                }
            }
        } catch (e: Exception) {
            errorLogger("[Sentinel] Error parsing batch verdict payload: ${e.message} | Raw: $jsonBody")
        }

        for (ip in requestedIps) {
            if (!out.containsKey(ip)) {
                out[ip] = SentinelVerdict.fallbackAllow(ip)
            }
        }
        return out
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

    internal fun parseVerdict(ip: String, jsonBody: String): SentinelVerdict {
        return try {
            val root = JsonParser.parseString(jsonBody).asJsonObject

            val action = if (root.has("action") && !root.get("action").isJsonNull) root.get("action").asString else "ALLOW"
            val riskScore = if (root.has("risk_score") && !root.get("risk_score").isJsonNull) root.get("risk_score").asInt else 0
            val confidence = if (root.has("confidence") && !root.get("confidence").isJsonNull) root.get("confidence").asDouble else (if (action == "ALLOW") 0.99 else 0.90)
            val threatType = if (root.has("threat_type") && !root.get("threat_type").isJsonNull) root.get("threat_type").asString else "Clean Residential"
            val isVpn = root.has("is_vpn") && !root.get("is_vpn").isJsonNull && root.get("is_vpn").asBoolean
            val isGamingOptimizer = root.has("is_gaming_optimizer") && !root.get("is_gaming_optimizer").isJsonNull && root.get("is_gaming_optimizer").asBoolean
            val isPrivacyRelay = root.has("is_privacy_relay") && !root.get("is_privacy_relay").isJsonNull && root.get("is_privacy_relay").asBoolean
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
                isPrivacyRelay = isPrivacyRelay,
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
        val trimmed = ip.trim()
        val entry = cache[trimmed] ?: cache[getSubnetKey(trimmed)]
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
