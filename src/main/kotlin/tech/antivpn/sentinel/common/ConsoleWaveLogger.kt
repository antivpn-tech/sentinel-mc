package tech.antivpn.sentinel.common

import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Rate-limit-aware console logger that prints individual connection blocks/flags during calm periods
 * and automatically switches to a 5-second aggregated summary line during bot waves/floods.
 */
class ConsoleWaveLogger(
    private val infoLogger: (String) -> Unit,
    private val warnLogger: (String) -> Unit
) {
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "Sentinel-Console-Wave-Logger").apply { isDaemon = true }
    }

    private var burstCount = 0
    private var lastBurstWindowStart = 0L

    private var suppressedTotal = 0
    private var suppressedEnforceBlocks = 0
    private var suppressedGraduated = 0
    private var suppressedAudit = 0
    private var suppressedBlacklist = 0
    private val threatBreakdown = LinkedHashMap<String, Int>()

    init {
        scheduler.scheduleWithFixedDelay(::flushSummary, 5, 5, TimeUnit.SECONDS)
    }

    @Synchronized
    private fun shouldLogIndividually(now: Long = System.currentTimeMillis()): Boolean {
        if (now - lastBurstWindowStart > 2000L) {
            burstCount = 0
            lastBurstWindowStart = now
        }
        burstCount++
        return burstCount <= 2 && suppressedTotal == 0
    }

    @Synchronized
    fun logBlacklistBlock(playerName: String?, ip: String, now: Long = System.currentTimeMillis()) {
        if (shouldLogIndividually(now)) {
            warnLogger("[Sentinel] Blacklist: Blocked ${playerName ?: "Unknown"} ($ip)")
        } else {
            suppressedTotal++
            suppressedBlacklist++
            threatBreakdown["Blacklist"] = (threatBreakdown["Blacklist"] ?: 0) + 1
        }
    }

    @Synchronized
    fun logEnforceBlock(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        if (shouldLogIndividually(now)) {
            warnLogger("[Sentinel] ENFORCE: Blocked ${playerName ?: "Unknown"} ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100]")
        } else {
            suppressedTotal++
            suppressedEnforceBlocks++
            threatBreakdown[verdict.threatType] = (threatBreakdown[verdict.threatType] ?: 0) + 1
        }
    }

    @Synchronized
    fun logGraduatedDefense(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        if (shouldLogIndividually(now)) {
            warnLogger(
                "[Sentinel] GRADUATED DEFENSE: Flagged ${playerName ?: "Unknown"} ($ip) - ${verdict.threatType} [Risk: ${verdict.riskScore}/100, Confidence: ${verdict.confidence}]. Connection allowed; alert dispatched."
            )
        } else {
            suppressedTotal++
            suppressedGraduated++
            threatBreakdown[verdict.threatType] = (threatBreakdown[verdict.threatType] ?: 0) + 1
        }
    }

    @Synchronized
    fun logAuditFlag(playerName: String?, ip: String, verdict: SentinelVerdict, now: Long = System.currentTimeMillis()) {
        if (shouldLogIndividually(now)) {
            infoLogger(
                "[Sentinel] AUDIT: Flagged ${playerName ?: "Unknown"} ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100] (Player Allowed - Audit Mode)"
            )
        } else {
            suppressedTotal++
            suppressedAudit++
            threatBreakdown[verdict.threatType] = (threatBreakdown[verdict.threatType] ?: 0) + 1
        }
    }

    @Synchronized
    fun flushSummary() {
        if (suppressedTotal <= 0) return

        val total = suppressedTotal
        val blocked = suppressedEnforceBlocks + suppressedBlacklist
        val graduated = suppressedGraduated
        val audit = suppressedAudit

        val actionParts = mutableListOf<String>()
        if (blocked > 0) actionParts.add("$blocked blocked")
        if (graduated > 0) actionParts.add("$graduated graduated defense")
        if (audit > 0) actionParts.add("$audit audited")

        val topThreats = threatBreakdown.entries
            .sortedByDescending { it.value }
            .take(4)
            .joinToString(", ") { "${it.key}: ${it.value}" }

        suppressedTotal = 0
        suppressedEnforceBlocks = 0
        suppressedGraduated = 0
        suppressedAudit = 0
        suppressedBlacklist = 0
        threatBreakdown.clear()

        val breakdownSuffix = if (topThreats.isNotEmpty()) " | Threats: $topThreats" else ""
        val summary = "[Sentinel] Threat Wave Summary (5s): $total connections intercepted (${actionParts.joinToString(", ")}$breakdownSuffix)"

        if (blocked > 0 || graduated > 0) {
            warnLogger(summary)
        } else {
            infoLogger(summary)
        }
    }

    fun shutdown() {
        scheduler.shutdown()
        flushSummary()
    }
}
