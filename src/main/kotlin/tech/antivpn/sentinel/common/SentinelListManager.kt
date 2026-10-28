package tech.antivpn.sentinel.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe Whitelist and Blacklist manager supporting both IP addresses and Minecraft usernames.
 * Persists data to JSON files in the plugin data directory.
 */
class SentinelListManager(
    private val dataDirectory: Path,
    private val infoLogger: (String) -> Unit = {},
    private val warnLogger: (String) -> Unit = {}
) {
    private val gson: Gson = GsonBuilder().setPrettyPrinting().create()

    private val whitelistedPlayers: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val whitelistedIps: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val blacklistedPlayers: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val blacklistedIps: MutableSet<String> = ConcurrentHashMap.newKeySet()

    init {
        load()
    }

    @Synchronized
    fun load() {
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory)
            }

            loadListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
            loadListFile("blacklist.json", blacklistedPlayers, blacklistedIps)

            infoLogger("[Sentinel] Loaded lists: ${whitelistedPlayers.size} whitelisted players, ${whitelistedIps.size} whitelisted IPs | ${blacklistedPlayers.size} blacklisted players, ${blacklistedIps.size} blacklisted IPs.")
        } catch (e: Exception) {
            warnLogger("[Sentinel] Error loading whitelist/blacklist: ${e.message}")
        }
    }

    private fun loadListFile(filename: String, playerSet: MutableSet<String>, ipSet: MutableSet<String>) {
        playerSet.clear()
        ipSet.clear()

        val file = dataDirectory.resolve(filename)
        if (!Files.exists(file)) {
            saveListFile(filename, playerSet, ipSet)
            return
        }

        try {
            Files.newBufferedReader(file, StandardCharsets.UTF_8).use { reader ->
                val dto = gson.fromJson(reader, ListDto::class.java)
                if (dto != null) {
                    dto.players.filter { it.isNotBlank() }.forEach {
                        playerSet.add(it.trim().lowercase(Locale.ROOT))
                    }
                    dto.ips.filter { it.isNotBlank() }.forEach {
                        ipSet.add(it.trim())
                    }
                }
            }
        } catch (e: Exception) {
            warnLogger("[Sentinel] Failed to parse $filename: ${e.message}")
        }
    }

    @Synchronized
    private fun saveListFile(filename: String, playerSet: Set<String>, ipSet: Set<String>) {
        val file = dataDirectory.resolve(filename)
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory)
            }
            val dto = ListDto(
                players = playerSet.sortedWith(String.CASE_INSENSITIVE_ORDER),
                ips = ipSet.sorted()
            )

            Files.newBufferedWriter(file, StandardCharsets.UTF_8).use { writer ->
                gson.toJson(dto, writer)
            }
        } catch (e: IOException) {
            warnLogger("[Sentinel] Failed to save $filename: ${e.message}")
        }
    }

    fun isWhitelisted(username: String?, ip: String?): Boolean {
        if (!username.isNullOrBlank() && whitelistedPlayers.contains(username.trim().lowercase(Locale.ROOT))) {
            return true
        }
        if (!ip.isNullOrBlank() && whitelistedIps.contains(ip.trim())) {
            return true
        }
        return false
    }

    fun isBlacklisted(username: String?, ip: String?): Boolean {
        if (!username.isNullOrBlank() && blacklistedPlayers.contains(username.trim().lowercase(Locale.ROOT))) {
            return true
        }
        if (!ip.isNullOrBlank() && blacklistedIps.contains(ip.trim())) {
            return true
        }
        return false
    }

    fun addWhitelist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            whitelistedIps.add(clean)
        } else {
            whitelistedPlayers.add(clean.lowercase(Locale.ROOT))
        }
        if (changed) {
            saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
        }
        return changed
    }

    fun removeWhitelist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            whitelistedIps.remove(clean)
        } else {
            whitelistedPlayers.remove(clean.lowercase(Locale.ROOT))
        }
        if (changed) {
            saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
        }
        return changed
    }

    fun addBlacklist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            blacklistedIps.add(clean)
        } else {
            blacklistedPlayers.add(clean.lowercase(Locale.ROOT))
        }
        if (changed) {
            saveListFile("blacklist.json", blacklistedPlayers, blacklistedIps)
        }
        return changed
    }

    fun removeBlacklist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            blacklistedIps.remove(clean)
        } else {
            blacklistedPlayers.remove(clean.lowercase(Locale.ROOT))
        }
        if (changed) {
            saveListFile("blacklist.json", blacklistedPlayers, blacklistedIps)
        }
        return changed
    }

    fun getWhitelistedPlayers(): Set<String> = Collections.unmodifiableSet(whitelistedPlayers)
    fun getWhitelistedIps(): Set<String> = Collections.unmodifiableSet(whitelistedIps)
    fun getBlacklistedPlayers(): Set<String> = Collections.unmodifiableSet(blacklistedPlayers)
    fun getBlacklistedIps(): Set<String> = Collections.unmodifiableSet(blacklistedIps)

    companion object {
        @JvmStatic
        fun isIpAddress(str: String?): Boolean {
            if (str.isNullOrBlank()) return false
            val clean = str.trim()
            return clean.contains(".") || clean.contains(":")
        }
    }

    private data class ListDto(
        val players: List<String> = emptyList(),
        val ips: List<String> = emptyList()
    )
}
