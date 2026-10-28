package tech.antivpn.sentinel.velocity

import com.velocitypowered.api.event.EventTask
import com.velocitypowered.api.event.Subscribe
import com.velocitypowered.api.event.connection.PreLoginEvent
import net.kyori.adventure.text.Component
import net.kyori.adventure.text.format.NamedTextColor
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer

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

        val config = plugin.sentinelConfig

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
                            val formattedKick = config.buildEnforcementKickMessage(
                                threat = verdict.threatType,
                                risk = verdict.riskScore,
                                ip = ip,
                                player = username
                            )
                            val kickComponent = LegacyComponentSerializer.legacyAmpersand().deserialize(formattedKick)

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
