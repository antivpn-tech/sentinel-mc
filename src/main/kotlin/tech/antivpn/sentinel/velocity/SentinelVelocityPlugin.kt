package tech.antivpn.sentinel.velocity

import com.google.inject.Inject
import com.velocitypowered.api.command.CommandMeta
import com.velocitypowered.api.event.Subscribe
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent
import com.velocitypowered.api.plugin.Plugin
import com.velocitypowered.api.plugin.annotation.DataDirectory
import com.velocitypowered.api.proxy.ProxyServer
import org.slf4j.Logger
import tech.antivpn.sentinel.common.DiscordWebhookNotifier
import tech.antivpn.sentinel.common.SentinelGate
import tech.antivpn.sentinel.common.SentinelClient
import tech.antivpn.sentinel.common.SentinelConfig
import tech.antivpn.sentinel.common.SentinelListManager
import java.io.BufferedReader
import java.nio.file.Files
import java.nio.file.Path

/**
 * Velocity Proxy implementation of the Sentinel Universal Anti-VPN Plugin.
 */
@Plugin(
    id = "sentinel",
    name = "Sentinel",
    version = "1.0.0",
    description = "Enterprise Anti-VPN, Proxy Evasion, and Sentinel Gate Protection for Velocity.",
    authors = ["Sentinel"]
)
class SentinelVelocityPlugin @Inject constructor(
    val server: ProxyServer,
    val logger: Logger,
    @DataDirectory val dataDirectory: Path
) {
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

    @Subscribe
    fun onProxyInitialization(event: ProxyInitializeEvent) {
        loadConfiguration()

        // Register async event listener
        server.eventManager.register(this, VelocityPreLoginListener(this))

        // Register command
        val commandManager = server.commandManager
        val meta: CommandMeta = commandManager.metaBuilder("sentinel")
            .aliases("antivpn")
            .plugin(this)
            .build()
        commandManager.register(meta, SentinelVelocityCommand(this))

        logger.info("==================================================")
        logger.info(" Sentinel Anti-VPN Connector v1.0.0 (Velocity)")
        logger.info(" Mode: {} {}", sentinelConfig.mode, if (sentinelConfig.isAuditMode) "(AUDIT - PASSIVE MONITORING)" else "(ACTIVE ENFORCEMENT - BLOCKING VPNS)")
        logger.info(" Risk Threshold: {} / 100", sentinelConfig.riskThreshold)
        logger.info(" Sentinel Gate: {}", if (sentinelConfig.antiBotEnabled) "ENABLED (Burst: ${sentinelConfig.antiBotBurstThreshold} conn/s)" else "DISABLED")
        logger.info(" Discord Alerts: {}", if (sentinelConfig.isDiscordConfigured) "ENABLED (Rate-Limit Batcher)" else "DISABLED")
        logger.info("==================================================")
    }

    @Subscribe
    fun onProxyShutdown(event: ProxyShutdownEvent) {
        if (::sentinelClient.isInitialized) {
            sentinelClient.clearCache()
        }
        if (::webhookNotifier.isInitialized) {
            webhookNotifier.shutdown()
        }
        logger.info("[Sentinel] Velocity proxy shutdown: cache cleared.")
    }

    fun loadConfiguration() {
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory)
            }

            val configPath = dataDirectory.resolve("config.yml")
            if (!Files.exists(configPath)) {
                javaClass.getResourceAsStream("/config.yml")?.use { input ->
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
            val serverName = props["discord.server-name"] ?: "Velocity Network"
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
                errorLogger = { logger.warn(it) }
            )

            this.webhookNotifier = DiscordWebhookNotifier(
                this.sentinelConfig,
                errorLogger = { logger.warn(it) }
            )

            this.sentinelGate = SentinelGate(
                this.sentinelConfig,
                infoLogger = { logger.info(it) },
                warnLogger = { logger.warn(it) }
            )

            if (!::listManager.isInitialized) {
                this.listManager = SentinelListManager(
                    dataDirectory,
                    infoLogger = { logger.info(it) },
                    warnLogger = { logger.warn(it) }
                )
            } else {
                this.listManager.load()
            }
        } catch (e: Exception) {
            logger.error("[Sentinel] Failed to load configuration: {}", e.message, e)
            this.sentinelConfig = SentinelConfig.createDefault()
            this.sentinelClient = SentinelClient(this.sentinelConfig, { logger.info(it) }, { logger.warn(it) })
            this.webhookNotifier = DiscordWebhookNotifier(this.sentinelConfig) { logger.warn(it) }
            this.sentinelGate = SentinelGate(this.sentinelConfig, { logger.info(it) }, { logger.warn(it) })
            this.listManager = SentinelListManager(dataDirectory, { logger.info(it) }, { logger.warn(it) })
        }
    }
}
