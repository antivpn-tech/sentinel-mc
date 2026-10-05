package tech.antivpn.sentinel.common

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-performance, rate-limit-aware Discord Webhook dispatcher for Sentinel threat intelligence alerts.
 * Features automatic flood aggregation to eliminate Discord HTTP 429 rate limit drops during bot attacks.
 */
class DiscordWebhookNotifier(
    private val config: SentinelConfig,
    private val errorLogger: (String) -> Unit = {}
) {
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    private val alertQueue = ConcurrentLinkedQueue<AlertItem>()
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        val t = Thread(r, "Sentinel-Discord-Batcher")
        t.isDaemon = true
        t
    }

    private val burstCounter = AtomicInteger(0)
    private var lastBurstReset = System.currentTimeMillis()

    private data class AlertItem(
        val playerName: String?,
        val verdict: SentinelVerdict,
        val wasEnforced: Boolean,
        val timestamp: Long = System.currentTimeMillis()
    )

    init {
        // Flush queued alerts every 1.5 seconds
        scheduler.scheduleWithFixedDelay(::flushQueue, 1500, 1500, TimeUnit.MILLISECONDS)
    }

    /**
     * Dispatches an asynchronous Discord notification, automatically batching under high-volume floods.
     */
    fun sendAlert(playerName: String?, verdict: SentinelVerdict, wasEnforced: Boolean): CompletableFuture<Void> {
        if (!config.isDiscordConfigured) {
            return CompletableFuture.completedFuture(null)
        }

        val now = System.currentTimeMillis()
        synchronized(this) {
            if (now - lastBurstReset > 1000) {
                burstCounter.set(0)
                lastBurstReset = now
            }
        }

        // If under normal rate (< 3 alerts/sec), send immediately for real-time responsiveness
        if (burstCounter.incrementAndGet() <= 2 && alertQueue.isEmpty()) {
            return dispatchSingleAlert(playerName, verdict, wasEnforced)
        }

        // Under burst flood, queue for consolidated batching
        alertQueue.add(AlertItem(playerName, verdict, wasEnforced))
        return CompletableFuture.completedFuture(null)
    }

    @Synchronized
    private fun flushQueue() {
        if (alertQueue.isEmpty()) return

        val drained = mutableListOf<AlertItem>()
        var item: AlertItem?
        while (alertQueue.poll().also { item = it } != null) {
            item?.let { drained.add(it) }
            if (drained.size >= 50) break
        }

        if (drained.isEmpty()) return

        if (drained.size <= 2) {
            for (a in drained) {
                dispatchSingleAlert(a.playerName, a.verdict, a.wasEnforced)
            }
        } else {
            dispatchAggregatedAttackAlert(drained)
        }
    }

    private fun dispatchSingleAlert(playerName: String?, verdict: SentinelVerdict, wasEnforced: Boolean): CompletableFuture<Void> {
        return try {
            val payload = JsonObject()
            payload.addProperty("username", "Sentinel Anti-VPN")

            val embed = JsonObject()
            val titlePrefix = if (wasEnforced) "[SENTINEL ENFORCE]" else "[SENTINEL AUDIT]"
            embed.addProperty("title", "$titlePrefix ${verdict.threatType} Flagged")
            embed.addProperty("color", if (wasEnforced) 0xEF4444 else 0xF59E0B)
            embed.addProperty("timestamp", Instant.now().toString())

            val fields = JsonArray()
            addField(fields, "Player", "`${playerName ?: "Unknown"}`", true)
            addField(fields, "IP Address", "`${verdict.ip}`", true)
            addField(fields, "Risk Rating", "**${verdict.riskScore} / 100** (${getRiskSeverity(verdict.riskScore)})", true)

            val ispVal = "AS${verdict.asn} - ${verdict.provider} (${verdict.getFormattedLocation()})"
            addField(fields, "ISP & Network Details", ispVal, false)
            addField(fields, "Threat Classification", "${verdict.threatType} [Verdict: ${verdict.action}]", true)
            addField(fields, "Action Taken", if (wasEnforced) "BLOCKED (Player Kicked)" else "AUDIT (Player Allowed - Dry Run Test)", true)

            val reasons = verdict.reasons
            if (reasons.isNotEmpty()) {
                val sb = StringBuilder()
                for (r in reasons) {
                    sb.append("• ").append(r).append("\n")
                }
                val text = if (sb.length > 1024) sb.substring(0, 1021) + "..." else sb.toString()
                addField(fields, "Detection Reasons", text, false)
            }

            embed.add("fields", fields)

            val footer = JsonObject()
            footer.addProperty("text", "Server: ${config.discordServerName} | Edge Latency: ${verdict.durationMs}ms")
            embed.add("footer", footer)

            val embedsArray = JsonArray()
            embedsArray.add(embed)
            payload.add("embeds", embedsArray)

            postWebhook(payload.toString())
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct single webhook: ${e.message}")
            CompletableFuture.completedFuture(null)
        }
    }

    private fun dispatchAggregatedAttackAlert(batch: List<AlertItem>): CompletableFuture<Void> {
        return try {
            val payload = JsonObject()
            payload.addProperty("username", "Sentinel Gate")

            val embed = JsonObject()
            embed.addProperty("title", "[SENTINEL GATE] High-Volume Bot Attack Neutralized")
            embed.addProperty("description", "**${batch.size} malicious connections** were intercepted and neutralized at the gate.")
            embed.addProperty("color", 0xEF4444)
            embed.addProperty("timestamp", Instant.now().toString())

            val fields = JsonArray()
            addField(fields, "Attacks Intercepted", "**${batch.size} connections**", true)

            val threatCounts = mutableMapOf<String, Int>()
            val samplePlayers = LinkedHashSet<String>()
            val uniqueCountries = LinkedHashSet<String>()

            for (item in batch) {
                threatCounts[item.verdict.threatType] = (threatCounts[item.verdict.threatType] ?: 0) + 1
                if (!item.playerName.isNullOrBlank() && samplePlayers.size < 8) {
                    samplePlayers.add(item.playerName)
                }
                if (item.verdict.country.isNotBlank() && item.verdict.country != "ZZ") {
                    uniqueCountries.add(item.verdict.country)
                }
            }

            val threatsSummary = StringBuilder()
            for ((k, v) in threatCounts) {
                threatsSummary.append("• **$k**: $v\n")
            }
            addField(fields, "Threat Breakdown", threatsSummary.toString(), false)

            if (samplePlayers.isNotEmpty()) {
                addField(fields, "Sample Bots", samplePlayers.joinToString(", "), false)
            }

            if (uniqueCountries.isNotEmpty()) {
                addField(fields, "Origin Countries", uniqueCountries.joinToString(", "), true)
            }

            embed.add("fields", fields)

            val footer = JsonObject()
            footer.addProperty("text", "Server: ${config.discordServerName} | Sentinel Gate Protection Active")
            embed.add("footer", footer)

            val embedsArray = JsonArray()
            embedsArray.add(embed)
            payload.add("embeds", embedsArray)

            postWebhook(payload.toString())
        } catch (e: Exception) {
            errorLogger("[Sentinel] Failed to construct batch webhook: ${e.message}")
            CompletableFuture.completedFuture(null)
        }
    }

    private fun postWebhook(jsonPayload: String): CompletableFuture<Void> {
        val request = HttpRequest.newBuilder()
            .uri(URI.create(config.discordWebhookUrl))
            .timeout(Duration.ofSeconds(4))
            .header("Content-Type", "application/json")
            .header("User-Agent", "Sentinel-Minecraft-Discord/1.0.0")
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build()

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
            .thenAccept { res ->
                if (res.statusCode() >= 400) {
                    errorLogger("[Sentinel] Discord webhook rejected with HTTP status ${res.statusCode()}")
                }
            }
            .exceptionally { ex ->
                errorLogger("[Sentinel] Failed to deliver Discord webhook: ${ex.message}")
                null
            }
    }

    private fun addField(fields: JsonArray, name: String, value: String, inline: Boolean) {
        val f = JsonObject()
        f.addProperty("name", name)
        f.addProperty("value", value)
        f.addProperty("inline", inline)
        fields.add(f)
    }

    private fun getRiskSeverity(score: Int): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 70 -> "HIGH"
            score >= 40 -> "MEDIUM"
            else -> "LOW"
        }
    }

    fun shutdown() {
        flushQueue()
        scheduler.shutdown()
    }
}
