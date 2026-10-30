package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.ChatColor
import net.md_5.bungee.api.chat.TextComponent
import net.md_5.bungee.api.event.PreLoginEvent
import net.md_5.bungee.api.plugin.Listener
import net.md_5.bungee.event.EventHandler
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

/**
 * High-performance asynchronous PreLoginEvent handler for BungeeCord and Waterfall proxy networks.
 */
class BungeePreLoginListener(private val plugin: SentinelBungeePlugin) : Listener {

    @EventHandler(priority = -64) // LOWEST priority
    fun onPreLogin(event: PreLoginEvent) {
        if (event.isCancelled) return
        val playerName = event.connection.name
        val socketAddress = event.connection.address as? InetSocketAddress ?: return
        val inetAddress = socketAddress.address ?: return
        val ip = inetAddress.hostAddress.substringBefore('%')

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(playerName, ip)) {
            plugin.logger.info("[Sentinel] Whitelist: Allowed $playerName ($ip)")
            return
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(playerName, ip)) {
            val kickMessage = "${ChatColor.RED}You are blacklisted from this server by Sentinel."
            event.isCancelled = true
            event.setCancelReason(*TextComponent.fromLegacyText(kickMessage))
            plugin.logger.warning("[Sentinel] Blacklist: Blocked $playerName ($ip)")
            return
        }

        // Register async intent for non-blocking callback execution
        val config = plugin.sentinelConfig
        event.registerIntent(plugin)
        plugin.sentinelClient.evaluate(ip)
            .orTimeout(config.safeTimeoutMs + 1000L, TimeUnit.MILLISECONDS)
            .whenComplete { verdict, ex ->
                try {
                    if (ex != null || verdict == null) {
                        plugin.logger.severe("[Sentinel] BungeeCord evaluation error for $playerName ($ip): ${ex?.message ?: "timeout"}")
                        return@whenComplete
                    }
                    val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)

                    if (isThreat || !config.discordNotifyOnlyOnThreat) {
                        val enforce = !config.isAuditMode

                        if (enforce && isThreat) {
                            if (config.graduatedDefense && !verdict.isHardThreat(config.riskThreshold, config.allowGamingOptimizers)) {
                                // Graduated Defense: Allow connection to protect legitimate players on shared mobile CGNAT pools, but alert staff
                                plugin.webhookNotifier.sendAlert(playerName, verdict, false)
                                plugin.logger.warning(
                                    "[Sentinel] GRADUATED DEFENSE: Flagged $playerName ($ip) - ${verdict.threatType} [Risk: ${verdict.riskScore}/100, Confidence: ${verdict.confidence}]. Connection allowed; alert dispatched."
                                )
                            } else {
                                // Deterministic hard threat: Enforce kick
                                plugin.webhookNotifier.sendAlert(playerName, verdict, true)
                                val kickMessage = ChatColor.translateAlternateColorCodes(
                                    '&',
                                    config.buildEnforcementKickMessage(
                                        threat = verdict.threatType,
                                        risk = verdict.riskScore,
                                        ip = ip,
                                        player = playerName
                                    )
                                )
                                event.isCancelled = true
                                event.setCancelReason(*TextComponent.fromLegacyText(kickMessage))
                                plugin.logger.warning(
                                    "[Sentinel] ENFORCE: Blocked $playerName ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100]"
                                )
                            }
                        } else {
                            plugin.webhookNotifier.sendAlert(playerName, verdict, false)
                            if (isThreat) {
                                plugin.logger.info(
                                    "[Sentinel] AUDIT: Flagged $playerName ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100] (Player Allowed - Audit Mode)"
                                )
                            }
                        }
                    }
                } catch (e: Exception) {
                    plugin.logger.severe("[Sentinel] BungeeCord evaluation error for $playerName ($ip): ${e.message ?: e.javaClass.simpleName}")
                } finally {
                    event.completeIntent(plugin)
                }
            }
    }
}
