package tech.antivpn.sentinel.bungee

import net.md_5.bungee.api.plugin.Plugin
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
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
        logger.info(" Graduated Defense: " + if (sentinelConfig.graduatedDefense) "ENABLED (Soft-alert suspect residential)" else "DISABLED")
        logger.info(" Discord Alerts: " + if (sentinelConfig.isDiscordConfigured) "ENABLED (Rate-Limit Batcher)" else "DISABLED")
        logger.info("==================================================")

        if (sentinelConfig.licenseKey == "stl_live_your_api_key_here" || sentinelConfig.licenseKey == "stl_test_showcase_demo" || sentinelConfig.licenseKey.isBlank()) {
            logger.warning("*************************************************************************")
            if (sentinelConfig.licenseKey == "stl_test_showcase_demo") {
                logger.warning("[Sentinel] WARNING: Public demo sandbox key (stl_test_showcase_demo) in use!")
                logger.warning("[Sentinel] Demo keys are strictly rate-limited (50 req/day) across all servers.")
            } else {
                logger.warning("[Sentinel] WARNING: No production Sentinel API license key configured!")
            }
            logger.warning("[Sentinel] Running in ${sentinelConfig.mode} mode without a production license key.")
            logger.warning("[Sentinel] Requests exceeding limits will fail-open. Configure your key in config.yml.")
            logger.warning("*************************************************************************")
        }
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
                    var currentKey: String? = null
                    while (reader.readLine().also { line = it } != null) {
                        val trimmed = line!!.trim()
                        if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

                        if (trimmed.endsWith(":") && !trimmed.contains(" ")) {
                            currentSection = trimmed.substring(0, trimmed.length - 1) + "."
                            currentKey = null
                            continue
                        }

                        if (trimmed.startsWith("-") && currentKey != null) {
                            var item = trimmed.substring(1).trim()
                            if ((item.startsWith("\"") && item.endsWith("\"")) || (item.startsWith("'") && item.endsWith("'"))) {
                                item = item.substring(1, item.length - 1)
                            }
                            val existing = props[currentKey]
                            props[currentKey] = if (existing.isNullOrEmpty()) item else "$existing\n$item"
                            continue
                        }

                        val colonIdx = trimmed.indexOf(':')
                        if (colonIdx > 0) {
                            val key = trimmed.substring(0, colonIdx).trim()
                            var value = trimmed.substring(colonIdx + 1).trim()
                            if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
                                value = value.substring(1, value.length - 1)
                            }
                            currentKey = currentSection + key
                            props[currentKey] = value
                        } else {
                            currentKey = null
                        }
                    }
                }
            }

            val endpoint = props["api.endpoint"] ?: "https://api.antivpn.tech/v1/check"
            val licenseKey = props["api.license-key"] ?: "stl_live_your_api_key_here"
            val timeoutMs = props["api.timeout-ms"]?.toIntOrNull() ?: 2500
            val mode = props["mode"] ?: "ENFORCE"
            val riskThreshold = props["risk-threshold"]?.toIntOrNull() ?: 80
            val allowGaming = props["allow-gaming-optimizers"]?.toBooleanStrictOrNull() ?: true
            val graduatedDefense = props["graduated-defense"]?.toBooleanStrictOrNull() ?: true
            val cacheMinutes = props["cache-duration-minutes"]?.toIntOrNull() ?: 30
            val discordEnabled = props["discord.enabled"]?.toBooleanStrictOrNull() ?: true
            val webhookUrl = props["discord.webhook-url"] ?: ""
            val notifyOnlyThreat = props["discord.notify-only-on-threat"]?.toBooleanStrictOrNull() ?: true
            val serverName = props["discord.server-name"] ?: "BungeeCord Network"
            val kickMessage = props["enforcement.kick-message"]
                ?: "&7VPN / Proxy traffic is restricted on this server.\n&8Threat: &f%threat% &7| &8Risk: &f%risk%/100\n&7Join our Discord (&fhttps://discord.gg/yourlink&7) to request VPN access."

            this.sentinelConfig = SentinelConfig(
                endpoint = endpoint,
                licenseKey = licenseKey,
                timeoutMs = timeoutMs,
                mode = mode,
                riskThreshold = riskThreshold,
                allowGamingOptimizers = allowGaming,
                graduatedDefense = graduatedDefense,
                cacheDurationMinutes = cacheMinutes,
                discordEnabled = discordEnabled,
                discordWebhookUrl = webhookUrl,
                discordNotifyOnlyOnThreat = notifyOnlyThreat,
                discordServerName = serverName,
                kickMessage = kickMessage
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
            this.listManager = SentinelListManager(dataFolder.toPath(), { logger.info(it) }, { logger.warning(it) })
        }
    }
}
