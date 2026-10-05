package tech.antivpn.sentinel.paper

import org.bukkit.ChatColor
import org.bukkit.event.EventHandler
import org.bukkit.event.EventPriority
import org.bukkit.event.Listener
import org.bukkit.event.player.AsyncPlayerPreLoginEvent

/**
 * Event listener handling asynchronous player pre-login connection verification on Paper/Spigot/Bukkit.
 */
class PaperPreLoginListener(private val plugin: SentinelPaperPlugin) : Listener {

    @EventHandler(priority = EventPriority.LOWEST)
    fun onAsyncPlayerPreLogin(event: AsyncPlayerPreLoginEvent) {
        val playerName = event.name
        val address = event.address ?: return
        val ip = address.hostAddress

        // 1. Whitelist Check (Fastest Path - Bypasses edge API query)
        if (plugin.listManager.isWhitelisted(playerName, ip)) {
            plugin.logger.info("[Sentinel] Whitelist: Allowed $playerName ($ip)")
            return
        }

        // 2. Blacklist Check (Immediate Rejection)
        if (plugin.listManager.isBlacklisted(playerName, ip)) {
            val kickMessage = "${ChatColor.RED}You are blacklisted from this server by Sentinel."
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, kickMessage)
            plugin.logger.warning("[Sentinel] Blacklist: Blocked $playerName ($ip)")
            return
        }

        // 3. Sentinel Gate Anti-Bot Burst Protection (Fast In-Memory Socket Guard)
        val config = plugin.sentinelConfig
        val isCached = plugin.sentinelClient.isCached(ip)
        if (plugin.sentinelGate.shouldThrottle(ip, isCached)) {
            val kickMessage = ChatColor.translateAlternateColorCodes('&', config.antiBotKickMessage)
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMessage)
            plugin.logger.warning("[Sentinel Gate] Intercepted rapid burst connection from $playerName ($ip)")
            return
        }

        try {
            // Evaluate IP asynchronously against Sentinel Edge API
            val verdict = plugin.sentinelClient.evaluate(ip).join()

            val isThreat = verdict.isThreat(config.riskThreshold, config.allowGamingOptimizers)

            if (isThreat || !config.discordNotifyOnlyOnThreat) {
                val enforce = !config.isAuditMode

                // Dispatch Discord Webhook asynchronously
                plugin.webhookNotifier.sendAlert(playerName, verdict, enforce)

                if (enforce) {
                    val kickMessage = ChatColor.translateAlternateColorCodes(
                        '&',
                        config.kickMessage
                            .replace("%threat%", verdict.threatType)
                            .replace("%risk%", verdict.riskScore.toString())
                            .replace("%ip%", ip)
                            .replace("%player%", playerName)
                    )
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, kickMessage)
                    plugin.logger.warning(
                        "[Sentinel] ENFORCE: Blocked $playerName ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100]"
                    )
                } else {
                    plugin.logger.info(
                        "[Sentinel] AUDIT: Flagged $playerName ($ip) - Threat: ${verdict.threatType} [Risk: ${verdict.riskScore}/100] (Player Allowed - Audit Mode)"
                    )
                }
            }
        } catch (e: Exception) {
            plugin.logger.severe("[Sentinel] Unexpected error evaluating $playerName ($ip): ${e.message}")
        }
    }
}
