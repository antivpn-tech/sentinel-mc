package tech.antivpn.sentinel.common

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import tech.antivpn.sentinel.common.model.SentinelVerdict
import java.nio.file.Path

class SentinelCommonTest {

    @Test
    fun testConfigDefaultsAreEnforce() {
        val config = SentinelConfig.createDefault()
        assertEquals("ENFORCE", config.mode)
        assertFalse(config.isAuditMode)
        assertEquals(80, config.riskThreshold)
        assertTrue(config.allowGamingOptimizers)
        assertTrue(config.antiBotEnabled)
    }

    @Test
    fun testVerdictThreatEvaluation() {
        val vpnVerdict = SentinelVerdict(
            ip = "1.1.1.1",
            action = "BLOCK",
            riskScore = 95,
            threatType = "Proxy/VPN",
            isVpn = true,
            isGamingOptimizer = false
        )
        assertTrue(vpnVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))

        val gamingVerdict = SentinelVerdict(
            ip = "2.2.2.2",
            action = "BLOCK",
            riskScore = 90,
            threatType = "Gaming Optimizer",
            isVpn = true,
            isGamingOptimizer = true
        )
        // Gaming optimizer should be allowed when allowGamingOptimizers is true
        assertFalse(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        // And blocked when allowGamingOptimizers is false
        assertTrue(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = false))

        val cleanVerdict = SentinelVerdict(
            ip = "3.3.3.3",
            action = "ALLOW",
            riskScore = 0,
            threatType = "Clean Residential",
            isVpn = false,
            isGamingOptimizer = false
        )
        assertFalse(cleanVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
    }

    @Test
    fun testSentinelGateActivation() {
        val config = SentinelConfig(
            antiBotEnabled = true,
            antiBotBurstThreshold = 3,
            antiBotShieldDurationSeconds = 10,
            antiBotQuarantineSeconds = 20
        )
        val gate = SentinelGate(config)

        assertFalse(gate.shouldThrottle("10.0.0.1", isCached = false))
        assertFalse(gate.shouldThrottle("10.0.0.2", isCached = false))
        assertFalse(gate.shouldThrottle("10.0.0.3", isCached = false))

        // 4th connection in rapid succession exceeds threshold 3 -> triggers Sentinel Gate
        assertTrue(gate.shouldThrottle("10.0.0.4", isCached = false))
        assertTrue(gate.isGateActive())

        // Gate active -> any new unverified connection is throttled
        assertTrue(gate.shouldThrottle("10.0.0.5", isCached = false))

        // Cached players pass Sentinel Gate freely
        assertFalse(gate.shouldThrottle("10.0.0.99", isCached = true))
    }

    @Test
    fun testListManagerPersistence(@TempDir tempDir: Path) {
        val manager = SentinelListManager(tempDir)

        assertTrue(manager.addWhitelist("notch"))
        assertTrue(manager.addWhitelist("1.2.3.4"))
        assertTrue(manager.isWhitelisted("notch", null))
        assertTrue(manager.isWhitelisted(null, "1.2.3.4"))
        assertFalse(manager.isWhitelisted("jeb", "5.6.7.8"))

        assertTrue(manager.addBlacklist("badplayer"))
        assertTrue(manager.addBlacklist("9.9.9.9"))
        assertTrue(manager.isBlacklisted("badplayer", null))
        assertTrue(manager.isBlacklisted(null, "9.9.9.9"))

        // Reload from disk to verify JSON persistence
        val reloaded = SentinelListManager(tempDir)
        assertTrue(reloaded.isWhitelisted("notch", "1.2.3.4"))
        assertTrue(reloaded.isBlacklisted("badplayer", "9.9.9.9"))
    }
}
