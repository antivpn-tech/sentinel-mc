package tech.antivpn.sentinel.velocity

import com.velocitypowered.api.event.EventTask
import com.velocitypowered.api.event.Subscribe
import com.velocitypowered.api.event.connection.PreLoginEvent
import net.kyori.adventure.text.Component
import net.kyori.adventure.text.format.NamedTextColor

/**
 * High-throughput asynchronous PreLoginEvent handler for Velocity proxy networks.
 */
class VelocityPreLoginListener(private val plugin: SentinelVelocityPlugin) {

    @Subscribe
    fun onPreLogin(event: PreLoginEvent): EventTask? {
        val username = event.username
        val remoteAddress = event.connection.remoteAddress ?: return null
        val address = remoteAddress.address ?: return null
        val ip = address.hostAddress

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(username, ip)) {
            plugin.logger.info("[Sentinel] Whitelist: Allowed {} ({})", username, ip)
            return null
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(username, ip)) {
            val kickComponent = Component.text("You are blacklisted from this server by Sentinel.", NamedTextColor.RED)
            event.result = PreLoginEvent.PreLoginComponentResult.denied(kickComponent)
            plugin.logger.warn("[Sentinel] Blacklist: Blocked {} ({})", username, ip)
            return null
        }

        // 3. Sentinel Gate Anti-Bot Burst Protection (Fast In-Memory Socket Guard)
        val config = plugin.sentinelConfig
        val isCached = plugin.sentinelClient.isCached(ip)
        if (plugin.sentinelGate.shouldThrottle(ip, isCached)) {
            val kickComponent = Component.text()
                .append(Component.text("Sentinel Gate\n", NamedTextColor.RED))
                .append(Component.text("Gate active due to abnormal connection velocity.\n", NamedTextColor.GRAY))
                .append(Component.text("Please reconnect in a few seconds.", NamedTextColor.WHITE))
                .build()
            event.result = PreLoginEvent.PreLoginComponentResult.denied(kickComponent)
            plugin.logger.warn("[Sentinel Gate] Intercepted rapid burst connection from {} ({})", username, ip)
            return null
        }

        return EventTask.async {
            try {
                // Non-blocking asynchronous edge query
                val verdict = plugin.sentinelClient.evaluate(ip).join()

                val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)

                if (isThreat || !config.discordNotifyOnlyOnThreat) {
                    val enforce = !config.isAuditMode

                    if (enforce && isThreat) {
                        val isSuspectResidential = verdict.isSuspectResidentialTunnel()
                        if (config.graduatedDefense && isSuspectResidential && !verdict.isHardThreat(config.riskThreshold, config.allowGamingOptimizers)) {
                            // Graduated Defense: Allow connection to protect legitimate players on shared mobile CGNAT pools, but alert staff
                            plugin.webhookNotifier.sendAlert(username, verdict, false)
                            plugin.logger.warn(
                                "[Sentinel] GRADUATED DEFENSE: Flagged {} ({}) - Suspect Residential Tunnel [Risk: {}/100, Confidence: {}]. Connection allowed; alert dispatched.",
                                username, ip, verdict.riskScore, verdict.confidence
                            )
                        } else {
                            // Deterministic hard threat: Enforce kick
                            plugin.webhookNotifier.sendAlert(username, verdict, true)
                            val kickComponent = Component.text()
                                .append(Component.text("Sentinel Protection\n", NamedTextColor.RED))
                                .append(Component.text("VPN / Proxy traffic is restricted on this network.\n", NamedTextColor.GRAY))
                                .append(Component.text("Threat: ", NamedTextColor.DARK_GRAY))
                                .append(Component.text("${verdict.threatType} | ", NamedTextColor.WHITE))
                                .append(Component.text("Risk: ", NamedTextColor.DARK_GRAY))
                                .append(Component.text("${verdict.riskScore}/100", NamedTextColor.WHITE))
                                .build()

                            event.result = PreLoginEvent.PreLoginComponentResult.denied(kickComponent)
                            plugin.logger.warn(
                                "[Sentinel] ENFORCE: Blocked {} ({}) - Threat: {} [Risk: {}/100]",
                                username, ip, verdict.threatType, verdict.riskScore
                            )
                        }
                    } else {
                        plugin.webhookNotifier.sendAlert(username, verdict, false)
                        if (isThreat) {
                            plugin.logger.info(
                                "[Sentinel] AUDIT: Flagged {} ({}) - Threat: {} [Risk: {}/100] (Player Allowed - Audit Mode)",
                                username, ip, verdict.threatType, verdict.riskScore
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                plugin.logger.error("[Sentinel] Velocity pre-login evaluation failure for {} ({}): {}", username, ip, e.message)
            }
        }
    }
}
