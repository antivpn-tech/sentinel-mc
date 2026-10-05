package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.plugin.Plugin
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelGate
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.nio.file.Files

/**
 * Main Plugin entrypoint for BungeeCord / Waterfall proxy networks.
 */
class SentinelBungeePlugin : Plugin() {

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
        loadConfiguration()

        // Register PreLogin event listener
        proxy.pluginManager.registerListener(this, BungeePreLoginListener(this))

        // Register Command
        proxy.pluginManager.registerCommand(this, SentinelBungeeCommand(this))

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v${description.version} (BungeeCord/Waterfall)")
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
        logger.info("[Sentinel] BungeeCord proxy shutdown: cache cleared.")
    }

    fun loadConfiguration() {
        try {
            if (!dataFolder.exists()) {
                dataFolder.mkdirs()
            }

            val configPath = dataFolder.toPath().resolve("config.yml")
            if (!Files.exists(configPath)) {
                getResourceAsStream("config.yml")?.use { input ->
                    Files.copy(input, configPath)
                }
            }

            val props = mutableMapOf<String, String>()
            if (Files.exists(configPath)) {
                Files.newBufferedReader(configPath).use { reader ->
                    var line: String?
                    var currentSection = ""
                    while (reader.readLine().also { line = it } != null) {
                        val trimmed = line!!.trim()
                        if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

                        if (trimmed.endsWith(":") && !trimmed.contains(" ")) {
                            currentSection = trimmed.substring(0, trimmed.length - 1) + "."
                            continue
                        }

                        val colonIdx = trimmed.indexOf(':')
                        if (colonIdx > 0) {
                            val key = trimmed.substring(0, colonIdx).trim()
                            var value = trimmed.substring(colonIdx + 1).trim()
                            if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
                                value = value.substring(1, value.length - 1)
                            }
                            props[currentSection + key] = value
                        }
                    }
                }
            }

            val endpoint = props["api.endpoint"] ?: "https://api.antivpn.tech/v1/check"
            val licenseKey = props["api.license-key"] ?: "stl_test_showcase_demo"
            val timeoutMs = props["api.timeout-ms"]?.toIntOrNull() ?: 2500
            val mode = props["mode"] ?: "ENFORCE"
            val riskThreshold = props["risk-threshold"]?.toIntOrNull() ?: 80
            val allowGaming = props["allow-gaming-optimizers"]?.toBooleanStrictOrNull() ?: true
            val cacheMinutes = props["cache-duration-minutes"]?.toIntOrNull() ?: 30
            val discordEnabled = props["discord.enabled"]?.toBooleanStrictOrNull() ?: true
            val webhookUrl = props["discord.webhook-url"] ?: ""
            val notifyOnlyThreat = props["discord.notify-only-on-threat"]?.toBooleanStrictOrNull() ?: true
            val serverName = props["discord.server-name"] ?: "BungeeCord Network"
            val kickMessage = props["enforcement.kick-message"]
                ?: "&c&lSentinel Protection\n&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100"
            val antiBotEnabled = props["anti-bot.enabled"]?.toBooleanStrictOrNull() ?: true
            val burstThreshold = props["anti-bot.burst-threshold"]?.toIntOrNull() ?: 5
            val shieldDuration = props["anti-bot.shield-duration-seconds"]?.toIntOrNull() ?: 15
            val quarantineSeconds = props["anti-bot.quarantine-seconds"]?.toIntOrNull() ?: 60
            val antiBotKickMessage = props["anti-bot.kick-message"]
                ?: "&c&lSentinel Gate\n&7Gate active due to abnormal connection velocity.\n&7Please reconnect in a few seconds."

            this.sentinelConfig = SentinelConfig(
                endpoint = endpoint,
                licenseKey = licenseKey,
                timeoutMs = timeoutMs,
                mode = mode,
                riskThreshold = riskThreshold,
                allowGamingOptimizers = allowGaming,
                cacheDurationMinutes = cacheMinutes,
                discordEnabled = discordEnabled,
                discordWebhookUrl = webhookUrl,
                discordNotifyOnlyOnThreat = notifyOnlyThreat,
                discordServerName = serverName,
                kickMessage = kickMessage,
                antiBotEnabled = antiBotEnabled,
                antiBotBurstThreshold = burstThreshold,
                antiBotShieldDurationSeconds = shieldDuration,
                antiBotQuarantineSeconds = quarantineSeconds,
                antiBotKickMessage = antiBotKickMessage
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
        } catch (e: Exception) {
            logger.severe("[Sentinel] Failed to load BungeeCord configuration: ${e.message}")
            this.sentinelConfig = SentinelConfig.createDefault()
            this.sentinelClient = SentinelClient(this.sentinelConfig, { logger.info(it) }, { logger.warning(it) })
            this.webhookNotifier = DiscordWebhookNotifier(this.sentinelConfig) { logger.warning(it) }
            this.sentinelGate = SentinelGate(this.sentinelConfig, { logger.info(it) }, { logger.warning(it) })
            this.listManager = SentinelListManager(dataFolder.toPath(), { logger.info(it) }, { logger.warning(it) })
        }
    }
}
