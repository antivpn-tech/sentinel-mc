package tech.antivpn.sentinel.paper

import org.bukkit.Bukkit
import org.bukkit.ChatColor
import org.bukkit.command.Command
import org.bukkit.command.CommandExecutor
import org.bukkit.command.CommandSender
import org.bukkit.command.TabCompleter
import org.bukkit.entity.Player
import org.bukkit.plugin.java.JavaPlugin
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelGate
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.util.Locale

/**
 * Main JavaPlugin entrypoint for Paper / Purpur / Spigot / Bukkit servers.
 */
class SentinelPaperPlugin : JavaPlugin(), CommandExecutor, TabCompleter {

    lateinit var sentinelConfig: SentinelConfig
        private set
    lateinit var sentinelClient: SentinelClient
        private set
    lateinit var webhookNotifier: DiscordWebhookNotifier
        private set
    lateinit var listManager: SentinelListManager
        private set
    lateinit var sentinelGate: SentinelGate
        private set

    override fun onEnable() {
        saveDefaultConfig()
        loadConfiguration()

        // Register pre-login event listener
        server.pluginManager.registerEvents(PaperPreLoginListener(this), this)

        // Register command & tab completer
        getCommand("sentinel")?.let {
            it.setExecutor(this)
            it.tabCompleter = this
        }

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v${description.version} (Paper/Spigot)")
        logger.info(" Mode: ${sentinelConfig.mode} " + if (sentinelConfig.isAuditMode) "(AUDIT - PASSIVE MONITORING)" else "(ACTIVE ENFORCEMENT - BLOCKING VPNS)")
        logger.info(" Risk Threshold: ${sentinelConfig.riskThreshold} / 100")
        logger.info(" Sentinel Gate: " + if (sentinelConfig.antiBotEnabled) "ENABLED (Burst: ${sentinelConfig.antiBotBurstThreshold} conn/s)" else "DISABLED")
        logger.info(" Discord Alerts: " + if (sentinelConfig.isDiscordConfigured) "ENABLED (Rate-Limit Batcher)" else "DISABLED")
        logger.info("==================================================")
    }

    override fun onDisable() {
        if (::sentinelClient.isInitialized) {
            sentinelClient.clearCache()
        }
        if (::webhookNotifier.isInitialized) {
            webhookNotifier.shutdown()
        }
        logger.info("[Sentinel] Disabled and cache purged.")
    }

    fun loadConfiguration() {
        reloadConfig()
        val c = config

        this.sentinelConfig = SentinelConfig(
            endpoint = c.getString("api.endpoint", "https://api.antivpn.tech/v1/check") ?: "https://api.antivpn.tech/v1/check",
            licenseKey = c.getString("api.license-key", "stl_test_showcase_demo") ?: "stl_test_showcase_demo",
            timeoutMs = c.getInt("api.timeout-ms", 2500),
            mode = c.getString("mode", "ENFORCE") ?: "ENFORCE",
            riskThreshold = c.getInt("risk-threshold", 80),
            allowGamingOptimizers = c.getBoolean("allow-gaming-optimizers", true),
            cacheDurationMinutes = c.getInt("cache-duration-minutes", 30),
            discordEnabled = c.getBoolean("discord.enabled", true),
            discordWebhookUrl = c.getString("discord.webhook-url", "") ?: "",
            discordNotifyOnlyOnThreat = c.getBoolean("discord.notify-only-on-threat", true),
            discordServerName = c.getString("discord.server-name", "Minecraft Network") ?: "Minecraft Network",
            kickMessage = c.getString(
                "enforcement.kick-message",
                "&c&lSentinel Protection\n&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100"
            ) ?: "&c&lSentinel Protection\n&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100",
            antiBotEnabled = c.getBoolean("anti-bot.enabled", true),
            antiBotBurstThreshold = c.getInt("anti-bot.burst-threshold", 5),
            antiBotShieldDurationSeconds = c.getInt("anti-bot.shield-duration-seconds", 15),
            antiBotQuarantineSeconds = c.getInt("anti-bot.quarantine-seconds", 60),
            antiBotKickMessage = c.getString(
                "anti-bot.kick-message",
                "&c&lSentinel Gate\n&7Gate active due to abnormal connection velocity.\n&7Please reconnect in a few seconds."
            ) ?: "&c&lSentinel Gate\n&7Gate active due to abnormal connection velocity.\n&7Please reconnect in a few seconds."
        )

        this.sentinelClient = SentinelClient(
            this.sentinelConfig,
            infoLogger = { logger.info(it) },
            errorLogger = { logger.warning(it) }
        )

        this.webhookNotifier = DiscordWebhookNotifier(
            this.sentinelConfig,
            errorLogger = { logger.warning(it) }
        )

        this.sentinelGate = SentinelGate(
            this.sentinelConfig,
            infoLogger = { logger.info(it) },
            warnLogger = { logger.warning(it) }
        )

        if (!::listManager.isInitialized) {
            this.listManager = SentinelListManager(
                dataFolder.toPath(),
                infoLogger = { logger.info(it) },
                warnLogger = { logger.warning(it) }
            )
        } else {
            this.listManager.load()
        }
    }

    override fun onCommand(sender: CommandSender, command: Command, label: String, args: Array<out String>): Boolean {
        if (!sender.hasPermission("sentinel.admin")) {
            sender.sendMessage("${ChatColor.RED}You do not have permission to execute Sentinel commands.")
            return true
        }

        if (args.isEmpty() || args[0].equals("status", ignoreCase = true)) {
            sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            sender.sendMessage("${ChatColor.GOLD}${ChatColor.BOLD}Sentinel Anti-VPN Status")
            sender.sendMessage("${ChatColor.GRAY}Mode: " + if (sentinelConfig.isAuditMode) "${ChatColor.YELLOW}AUDIT (Dry-Run)" else "${ChatColor.RED}ENFORCE (Blocking)")
            sender.sendMessage("${ChatColor.GRAY}Risk Threshold: ${ChatColor.WHITE}${sentinelConfig.riskThreshold} / 100")
            sender.sendMessage("${ChatColor.GRAY}Cached IPs: ${ChatColor.WHITE}${sentinelClient.cacheSize}")
            sender.sendMessage("${ChatColor.GRAY}Whitelisted: ${ChatColor.GREEN}${listManager.getWhitelistedPlayers().size} players, ${listManager.getWhitelistedIps().size} IPs")
            sender.sendMessage("${ChatColor.GRAY}Blacklisted: ${ChatColor.RED}${listManager.getBlacklistedPlayers().size} players, ${listManager.getBlacklistedIps().size} IPs")
            sender.sendMessage("${ChatColor.GRAY}Discord Webhook: " + if (sentinelConfig.isDiscordConfigured) "${ChatColor.GREEN}Connected" else "${ChatColor.RED}Disabled / Unset")
            sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            return true
        }

        if (args[0].equals("reload", ignoreCase = true)) {
            loadConfiguration()
            sender.sendMessage("${ChatColor.GREEN}[Sentinel] Configuration and whitelist/blacklist reloaded.")
            return true
        }

        // Whitelist commands: /sentinel whitelist [add|remove|list] <player|ip>
        if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.GREEN}${ChatColor.BOLD}Sentinel Whitelist")
                sender.sendMessage(
                    "${ChatColor.GRAY}Players (${listManager.getWhitelistedPlayers().size}): " +
                            ChatColor.WHITE + (if (listManager.getWhitelistedPlayers().isEmpty()) "None" else listManager.getWhitelistedPlayers().joinToString(", "))
                )
                sender.sendMessage(
                    "${ChatColor.GRAY}IPs (${listManager.getWhitelistedIps().size}): " +
                            ChatColor.WHITE + (if (listManager.getWhitelistedIps().isEmpty()) "None" else listManager.getWhitelistedIps().joinToString(", "))
                )
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                return true
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val added = listManager.addWhitelist(target)
                if (added) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Added '$target' to the whitelist.")
                } else {
                    sender.sendMessage("${ChatColor.YELLOW}[Sentinel] '$target' is already whitelisted.")
                }
                return true
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = listManager.removeWhitelist(target)
                if (removed) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Removed '$target' from the whitelist.")
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' was not found in the whitelist.")
                }
                return true
            }

            sender.sendMessage("${ChatColor.RED}Usage: /sentinel whitelist [add <player|ip> | remove <player|ip> | list]")
            return true
        }

        // Blacklist commands: /sentinel blacklist [add|remove|list] <player|ip>
        if (args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)) {
            if (args.size < 2 || args[1].equals("list", ignoreCase = true)) {
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.RED}${ChatColor.BOLD}Sentinel Blacklist")
                sender.sendMessage(
                    "${ChatColor.GRAY}Players (${listManager.getBlacklistedPlayers().size}): " +
                            ChatColor.WHITE + (if (listManager.getBlacklistedPlayers().isEmpty()) "None" else listManager.getBlacklistedPlayers().joinToString(", "))
                )
                sender.sendMessage(
                    "${ChatColor.GRAY}IPs (${listManager.getBlacklistedIps().size}): " +
                            ChatColor.WHITE + (if (listManager.getBlacklistedIps().isEmpty()) "None" else listManager.getBlacklistedIps().joinToString(", "))
                )
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                return true
            }

            if (args[1].equals("add", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val added = listManager.addBlacklist(target)
                if (added) {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] Added '$target' to the blacklist.")
                } else {
                    sender.sendMessage("${ChatColor.YELLOW}[Sentinel] '$target' is already blacklisted.")
                }
                return true
            }

            if (args[1].equals("remove", ignoreCase = true) && args.size >= 3) {
                val target = args[2]
                val removed = listManager.removeBlacklist(target)
                if (removed) {
                    sender.sendMessage("${ChatColor.GREEN}[Sentinel] Removed '$target' from the blacklist.")
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] '$target' was not found in the blacklist.")
                }
                return true
            }

            sender.sendMessage("${ChatColor.RED}Usage: /sentinel blacklist [add <player|ip> | remove <player|ip> | list]")
            return true
        }

        if (args[0].equals("check", ignoreCase = true) && args.size >= 2) {
            val targetInput = args[1]
            var targetIp = targetInput
            var displayName = targetInput

            if (!SentinelListManager.isIpAddress(targetInput)) {
                val onlinePlayer = Bukkit.getPlayer(targetInput)
                if (onlinePlayer != null && onlinePlayer.address != null) {
                    targetIp = onlinePlayer.address!!.address.hostAddress
                    displayName = "${onlinePlayer.name} ($targetIp)"
                } else {
                    sender.sendMessage("${ChatColor.RED}[Sentinel] Player '$targetInput' is not online. To check an offline target, provide their direct IP.")
                    return true
                }
            }

            sender.sendMessage("${ChatColor.GRAY}[Sentinel] Querying edge intelligence for $displayName...")
            val finalDisplay = displayName
            sentinelClient.evaluate(targetIp).thenAccept { verdict ->
                val color = when {
                    verdict.riskScore >= 80 -> ChatColor.RED
                    verdict.riskScore >= 40 -> ChatColor.YELLOW
                    else -> ChatColor.GREEN
                }
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
                sender.sendMessage("${ChatColor.GOLD}[Sentinel Result] ${ChatColor.WHITE}$finalDisplay")
                sender.sendMessage("${ChatColor.GRAY}Verdict Action: $color${verdict.action}")
                sender.sendMessage("${ChatColor.GRAY}Risk Score: $color${verdict.riskScore}/100")
                sender.sendMessage("${ChatColor.GRAY}Threat Type: ${ChatColor.WHITE}${verdict.threatType}")
                sender.sendMessage("${ChatColor.GRAY}ISP: ${ChatColor.WHITE}AS${verdict.asn} ${verdict.provider}")
                sender.sendMessage("${ChatColor.GRAY}Location: ${ChatColor.WHITE}${verdict.getFormattedLocation()}")
                if (verdict.reasons.isNotEmpty()) {
                    sender.sendMessage("${ChatColor.GRAY}Reasons: ${ChatColor.WHITE}${verdict.reasons.joinToString(", ")}")
                }
                sender.sendMessage("${ChatColor.DARK_GRAY}---------------------------------------------")
            }
            return true
        }

        sender.sendMessage("${ChatColor.RED}Usage: /sentinel [status | reload | check <ip|player> | whitelist | blacklist]")
        return true
    }

    override fun onTabComplete(sender: CommandSender, command: Command, alias: String, args: Array<out String>): List<String> {
        if (!sender.hasPermission("sentinel.admin")) {
            return emptyList()
        }

        if (args.size == 1) {
            val sub = listOf("status", "reload", "check", "whitelist", "blacklist")
            return sub.filter { it.startsWith(args[0].lowercase(Locale.ROOT)) }
        }

        if (args.size == 2) {
            if (args[0].equals("check", ignoreCase = true)) {
                return Bukkit.getOnlinePlayers().map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(args[1].lowercase(Locale.ROOT)) }
            }
            if (args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true) ||
                args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            ) {
                val sub = listOf("add", "remove", "list")
                return sub.filter { it.startsWith(args[1].lowercase(Locale.ROOT)) }
            }
        }

        if (args.size == 3) {
            val isWl = args[0].equals("whitelist", ignoreCase = true) || args[0].equals("wl", ignoreCase = true)
            val isBl = args[0].equals("blacklist", ignoreCase = true) || args[0].equals("bl", ignoreCase = true)
            if (isWl || isBl) {
                if (args[1].equals("add", ignoreCase = true)) {
                    return Bukkit.getOnlinePlayers().map { it.name }.filter { it.lowercase(Locale.ROOT).startsWith(args[2].lowercase(Locale.ROOT)) }
                }
                if (args[1].equals("remove", ignoreCase = true)) {
                    val pool = if (isWl) {
                        listManager.getWhitelistedPlayers() + listManager.getWhitelistedIps()
                    } else {
                        listManager.getBlacklistedPlayers() + listManager.getBlacklistedIps()
                    }
                    return pool.filter { it.lowercase(Locale.ROOT).startsWith(args[2].lowercase(Locale.ROOT)) }
                }
            }
        }

        return emptyList()
    }
}
