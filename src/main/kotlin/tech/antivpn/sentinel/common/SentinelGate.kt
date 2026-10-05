package tech.antivpn.sentinel.common

import java.util.Queue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong

/**
 * Sentinel Gate™ - Intelligent Join Velocity Limiter and Anti-Bot Burst Flood Protection.
 * Detects sudden spikes of unverified concurrent connections, activates an edge shield window,
 * and temporarily quarantines throttled bot IPs to prevent slow-retry attacks.
 */
class SentinelGate(
    private val config: SentinelConfig,
    private val infoLogger: (String) -> Unit = {},
    private val warnLogger: (String) -> Unit = {}
) {
    private val connectionTimestamps: Queue<Long> = ConcurrentLinkedQueue()
    private val gateActiveUntil = AtomicLong(0)
    private val quarantinedIps = ConcurrentHashMap<String, Long>()

    /**
     * Evaluates whether a connection should be throttled by Sentinel Gate.
     *
     * @param ip The remote IP address
     * @param isCached Whether this IP is already present in the in-memory cache
     * @return true if the connection should be throttled/kicked
     */
    fun shouldThrottle(ip: String?, isCached: Boolean): Boolean {
        if (!config.antiBotEnabled || ip.isNullOrBlank()) {
            return false
        }

        // Verified / cached IPs pass Sentinel Gate freely
        if (isCached) {
            return false
        }

        val now = System.currentTimeMillis()

        // 1. Check if IP is currently quarantined from a recent burst
        val quarantinedUntil = quarantinedIps[ip]
        if (quarantinedUntil != null) {
            if (now < quarantinedUntil) {
                return true
            } else {
                quarantinedIps.remove(ip)
            }
        }

        val gateUntil = gateActiveUntil.get()

        // 2. Check if Sentinel Gate is currently closed
        if (now < gateUntil) {
            quarantine(ip, now)
            return true
        }

        // 3. Track sliding 1000ms window
        connectionTimestamps.add(now)
        val oneSecAgo = now - 1000L
        while (connectionTimestamps.isNotEmpty() && (connectionTimestamps.peek() ?: 0L) < oneSecAgo) {
            connectionTimestamps.poll()
        }

        // 4. Trigger Sentinel Gate if burst threshold exceeded
        if (connectionTimestamps.size > config.antiBotBurstThreshold) {
            val newGateUntil = now + (config.antiBotShieldDurationSeconds * 1000L)
            gateActiveUntil.set(newGateUntil)
            warnLogger("[Sentinel Gate] Abnormal join velocity detected (${connectionTimestamps.size} conn/sec)! Sentinel Gate active for ${config.antiBotShieldDurationSeconds}s.")
            quarantine(ip, now)
            return true
        }

        return false
    }

    private fun quarantine(ip: String, now: Long) {
        val durationMs = config.antiBotQuarantineSeconds * 1000L
        if (durationMs > 0) {
            quarantinedIps[ip] = now + durationMs
            if (quarantinedIps.size > 5000) {
                quarantinedIps.entries.removeIf { it.value < now }
            }
        }
    }

    fun isGateActive(): Boolean = System.currentTimeMillis() < gateActiveUntil.get()

    fun isQuarantined(ip: String): Boolean {
        val until = quarantinedIps[ip] ?: return false
        return System.currentTimeMillis() < until
    }

    fun clearQuarantine() {
        quarantinedIps.clear()
    }
}
