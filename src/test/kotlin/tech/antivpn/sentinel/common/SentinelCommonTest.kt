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
    }

    @Test
    fun testVerdictThreatEvaluation() {
        val vpnVerdict = SentinelVerdict(
            ip = "1.1.1.1",
            action = "BLOCK",
            riskScore = 95,
            confidence = 0.98,
            threatType = "Commercial VPN",
            reasonCodes = listOf("CARRIER_COMMERCIAL_VPN", "HOSTING_INFRASTRUCTURE_MATCH"),
            isVpn = true,
            isGamingOptimizer = false
        )
        assertTrue(vpnVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertTrue(vpnVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(vpnVerdict.isSuspectResidentialTunnel())

        val residentialVerdict = SentinelVerdict(
            ip = "185.1.2.3",
            action = "ALLOW",
            riskScore = 75,
            confidence = 0.82,
            threatType = "Residential Proxy",
            reasonCodes = listOf("RESIDENTIAL_TUNNEL_PROXY"),
            isVpn = false,
            isGamingOptimizer = false
        )
        assertTrue(residentialVerdict.isSuspectResidentialTunnel())
        // In default enforce mode, suspect residential proxy is not a hard threat (graduated defense applies)
        assertFalse(residentialVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))

        val gamingVerdict = SentinelVerdict(
            ip = "2.2.2.2",
            action = "BLOCK",
            riskScore = 90,
            confidence = 0.95,
            threatType = "Gaming Optimizer",
            reasonCodes = listOf("GAMING_OPTIMIZER_ROUTE"),
            isVpn = true,
            isGamingOptimizer = true
        )
        // Gaming optimizer should be allowed when allowGamingOptimizers is true
        assertFalse(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(gamingVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        // And blocked when allowGamingOptimizers is false
        assertTrue(gamingVerdict.isThreat(threshold = 80, allowGamingOptimizers = false))
        assertTrue(gamingVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = false))

        val cleanVerdict = SentinelVerdict(
            ip = "3.3.3.3",
            action = "ALLOW",
            riskScore = 0,
            confidence = 0.99,
            threatType = "Clean Residential",
            reasonCodes = listOf("CARRIER_RESIDENTIAL_CLEAN"),
            isVpn = false,
            isGamingOptimizer = false
        )
        assertFalse(cleanVerdict.isThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(cleanVerdict.isHardThreat(threshold = 80, allowGamingOptimizers = true))
        assertFalse(cleanVerdict.isSuspectResidentialTunnel())

        val privacyRelayVerdict = SentinelVerdict(
            ip = "104.28.1.1",
            action = "ALLOW",
            riskScore = 35,
            confidence = 0.95,
            threatType = "Privacy Relay",
            reasonCodes = listOf("PRIVACY_RELAY_VERIFIED"),
            isVpn = false,
            isPrivacyRelay = true
        )
        // Privacy relay (e.g. Cloudflare WARP) should not be flagged when allowGamingOptimizers is true
        assertFalse(privacyRelayVerdict.isThreat(threshold = 30, allowGamingOptimizers = true))
        assertFalse(privacyRelayVerdict.isHardThreat(threshold = 30, allowGamingOptimizers = true))

        // Privacy relay should be flagged when allowGamingOptimizers is false
        assertTrue(privacyRelayVerdict.isThreat(threshold = 30, allowGamingOptimizers = false))
        assertTrue(privacyRelayVerdict.isHardThreat(threshold = 30, allowGamingOptimizers = false))
    }

    @Test
    fun testPrivacyRelayParsing() {
        val client = SentinelClient(SentinelConfig.createDefault())
        val json = """
            {
                "ip": "104.28.1.1",
                "action": "ALLOW",
                "risk_score": 35,
                "threat_type": "Privacy Relay",
                "is_vpn": false,
                "is_privacy_relay": true,
                "asn": 13335,
                "provider": "Cloudflare WARP",
                "reason_codes": ["PRIVACY_RELAY_VERIFIED"]
            }
        """.trimIndent()

        val verdict = client.parseVerdict("104.28.1.1", json)
        assertTrue(verdict.isPrivacyRelay)
        assertFalse(verdict.isVpn)
        assertEquals(35, verdict.riskScore)
        assertEquals("Privacy Relay", verdict.threatType)
        assertEquals("Cloudflare WARP", verdict.provider)
        assertFalse(verdict.isThreat(threshold = 30, allowGamingOptimizers = true))
        assertTrue(verdict.isThreat(threshold = 30, allowGamingOptimizers = false))
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

    @Test
    fun testBatchEndpointAndParsing() {
        val client = SentinelClient(SentinelConfig.createDefault())
        assertEquals(
            "https://api.antivpn.tech/v1/batch",
            client.resolveBatchEndpoint("https://api.antivpn.tech/v1/check")
        )
        assertEquals(
            "https://example.com/api/batch",
            client.resolveBatchEndpoint("https://example.com/api/check")
        )

        val batchJson = """
            {
                "count": 2,
                "results": [
                    {
                        "ip": "185.220.101.1",
                        "action": "BLOCK",
                        "risk_score": 99,
                        "confidence": 0.99,
                        "threat_type": "Tor Exit Node",
                        "is_vpn": true,
                        "reason_codes": ["TOR_EXIT_NODE"]
                    },
                    {
                        "ip": "8.8.8.8",
                        "action": "ALLOW",
                        "risk_score": 0,
                        "confidence": 0.99,
                        "threat_type": "Clean Residential",
                        "is_vpn": false,
                        "reason_codes": ["CARRIER_RESIDENTIAL_CLEAN"]
                    }
                ]
            }
        """.trimIndent()

        val parsed = client.parseBatchVerdicts(listOf("185.220.101.1", "8.8.8.8", "9.9.9.9"), batchJson)
        assertEquals(3, parsed.size)
        assertEquals("BLOCK", parsed["185.220.101.1"]?.action)
        assertEquals(99, parsed["185.220.101.1"]?.riskScore)
        assertEquals("ALLOW", parsed["8.8.8.8"]?.action)
        // Missing IP in batch response fails open safely
        assertEquals("ALLOW", parsed["9.9.9.9"]?.action)

        // Unconfigured key fails open on evaluateBatch without throwing
        val fallbackBatch = client.evaluateBatch(listOf("1.1.1.1", "127.0.0.1")).join()
        assertEquals("ALLOW", fallbackBatch["1.1.1.1"]?.action)
        assertEquals("ALLOW", fallbackBatch["127.0.0.1"]?.action)
    }

    @Test
    fun testForcedBlueKickHeader() {
        val config = SentinelConfig.createDefault()
        val message = config.buildEnforcementKickMessage(
            threat = "Commercial VPN",
            risk = 90,
            ip = "1.2.3.4",
            player = "TestPlayer"
        )

        // Line 1 must be strictly forced as &9&lSentinel Protection (Blue & Bold)
        val lines = message.split("\n")
        assertTrue(lines.isNotEmpty())
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertEquals("&9&lSentinel Protection", lines[0])
        assertTrue(lines[1].contains("VPN / Proxy traffic is restricted on this server."))
        assertTrue(lines[2].contains("Commercial VPN"))
        assertTrue(lines[2].contains("90/100"))
    }

    @Test
    fun testKickMessageForcedEvenWhenConfigEmpty() {
        // Even if server owner blanks out kickMessage, line 1 cannot be removed
        val blankConfig = SentinelConfig(kickMessage = "   ")
        val message = blankConfig.buildEnforcementKickMessage("Tor Exit Node", 99, "5.6.7.8", "BadActor")
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, message)
        assertEquals("&9&lSentinel Protection", message)
    }

    @Test
    fun testStripLegacySentinelProtectionHeader() {
        // Upgraded configs that still contain older red &c&l header must have it stripped to avoid duplicate lines
        val oldConfig = SentinelConfig(
            kickMessage = "&c&lSentinel Protection\n&7Custom server kick message\n&8Threat: %threat%"
        )
        val formatted = oldConfig.buildEnforcementKickMessage(threat = "Datacenter VPS", risk = 85, ip = "1.1.1.1", player = "Test")
        val lines = formatted.split("\n")
        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertEquals("&7Custom server kick message", lines[1])
        assertEquals("&8Threat: Datacenter VPS", lines[2])
        // Must NOT contain old &c&l header
        assertFalse(formatted.contains("&c&lSentinel Protection"))
    }

    @Test
    fun testNewlineAndSlashNNormalization() {
        // Test literal \n and /n conversion
        val slashNConfig = SentinelConfig(
            kickMessage = "&7First Line/n&7Second Line\\n&8Threat: %threat%/n&7Join (&fhttps://discord.gg/nothing&7) to appeal."
        )
        val message = slashNConfig.buildEnforcementKickMessage("Commercial VPN", 92, "9.9.9.9", "Player")
        val lines = message.split("\n")

        assertEquals(SentinelConfig.FORCED_KICK_HEADER, lines[0])
        assertEquals("&7First Line", lines[1])
        assertEquals("&7Second Line", lines[2])
        assertEquals("&8Threat: Commercial VPN", lines[3])
        assertEquals("&7Join (&fhttps://discord.gg/nothing&7) to appeal.", lines[4])

        // Verify URL containing /nothing was preserved and NOT split
        assertTrue(lines[4].contains("https://discord.gg/nothing"))
        assertFalse(lines[4].contains("https://discord.gg\n"))
    }
}
