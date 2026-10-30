package tech.antivpn.sentinel.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.io.IOException
import java.net.InetAddress
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
        val file = dataDirectory.resolve(filename)
        if (!Files.exists(file)) {
            playerSet.clear()
            ipSet.clear()
            saveListFile(filename, playerSet, ipSet)
            return
        }

        try {
            val loadedPlayers = LinkedHashSet<String>()
            val loadedIps = LinkedHashSet<String>()
            Files.newBufferedReader(file, StandardCharsets.UTF_8).use { reader ->
                val dto = gson.fromJson(reader, ListDto::class.java)
                if (dto != null) {
                    (dto.players ?: emptyList()).filterNotNull().filter { isValidUsername(it) }.forEach {
                        loadedPlayers.add(it.trim().lowercase(Locale.ROOT))
                    }
                    (dto.ips ?: emptyList()).filterNotNull().filter { isIpAddress(it) }.forEach {
                        loadedIps.add(normalizeIp(it))
                    }
                }
            }
            playerSet.clear()
            playerSet.addAll(loadedPlayers)
            ipSet.clear()
            ipSet.addAll(loadedIps)
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
        if (!ip.isNullOrBlank() && matchesIpOrCidr(ip, whitelistedIps)) {
            return true
        }
        return false
    }

    fun isBlacklisted(username: String?, ip: String?): Boolean {
        if (!username.isNullOrBlank() && blacklistedPlayers.contains(username.trim().lowercase(Locale.ROOT))) {
            return true
        }
        if (!ip.isNullOrBlank() && matchesIpOrCidr(ip, blacklistedIps)) {
            return true
        }
        return false
    }

    private fun matchesIpOrCidr(rawIp: String, ipSet: Set<String>): Boolean {
        val norm = normalizeIp(rawIp)
        if (ipSet.contains(norm)) return true
        for (entry in ipSet) {
            if (entry.contains('/') && isIpInCidr(norm, entry)) {
                return true
            }
        }
        return false
    }

    @Synchronized
    fun addWhitelist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            val norm = normalizeIp(clean)
            if (blacklistedIps.remove(norm)) {
                saveListFile("blacklist.json", blacklistedPlayers, blacklistedIps)
            }
            whitelistedIps.add(norm)
        } else {
            if (!isValidUsername(clean)) return false
            val norm = clean.lowercase(Locale.ROOT)
            if (blacklistedPlayers.remove(norm)) {
                saveListFile("blacklist.json", blacklistedPlayers, blacklistedIps)
            }
            whitelistedPlayers.add(norm)
        }
        if (changed) {
            saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
        }
        return changed
    }

    @Synchronized
    fun removeWhitelist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            whitelistedIps.remove(normalizeIp(clean))
        } else {
            whitelistedPlayers.remove(clean.lowercase(Locale.ROOT))
        }
        if (changed) {
            saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
        }
        return changed
    }

    @Synchronized
    fun addBlacklist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            val norm = normalizeIp(clean)
            if (whitelistedIps.remove(norm)) {
                saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
            }
            blacklistedIps.add(norm)
        } else {
            if (!isValidUsername(clean)) return false
            val norm = clean.lowercase(Locale.ROOT)
            if (whitelistedPlayers.remove(norm)) {
                saveListFile("whitelist.json", whitelistedPlayers, whitelistedIps)
            }
            blacklistedPlayers.add(norm)
        }
        if (changed) {
            saveListFile("blacklist.json", blacklistedPlayers, blacklistedIps)
        }
        return changed
    }

    @Synchronized
    fun removeBlacklist(target: String?): Boolean {
        if (target.isNullOrBlank()) return false
        val clean = target.trim()
        val changed = if (isIpAddress(clean)) {
            blacklistedIps.remove(normalizeIp(clean))
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
        private val IPV4_PART = Regex("""^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
        private val IPV6_CHARS = Regex("""^[0-9a-fA-F:.]+$""")
        private val USERNAME_REGEX = Regex("""^\.?[a-zA-Z0-9_]{1,32}$""")

        @JvmStatic
        fun isValidUsername(str: String?): Boolean {
            if (str.isNullOrBlank()) return false
            return USERNAME_REGEX.matches(str.trim())
        }

        @JvmStatic
        fun isValidTarget(str: String?): Boolean {
            if (str.isNullOrBlank()) return false
            val clean = str.trim()
            return isIpAddress(clean) || isValidUsername(clean)
        }

        private fun parseLiteralInetAddress(addr: String): InetAddress {
            val literal = if (addr.contains(':') && !addr.startsWith("[")) "[$addr]" else addr
            return InetAddress.getByName(literal)
        }

        @JvmStatic
        fun isSingleIpAddress(str: String?): Boolean {
            if (str.isNullOrBlank() || str.contains('/')) return false
            return isIpAddress(str)
        }

        @JvmStatic
        fun isIpAddress(str: String?): Boolean {
            if (str.isNullOrBlank()) return false
            val clean = str.trim().substringBefore('%')
            val slashIdx = clean.indexOf('/')
            val addrPart = (if (slashIdx >= 0) clean.substring(0, slashIdx) else clean).removeSurrounding("[", "]")
            val prefixPart = if (slashIdx >= 0) clean.substring(slashIdx + 1) else null

            if (IPV4_PART.matches(addrPart)) {
                if (prefixPart == null) return true
                val prefix = prefixPart.toIntOrNull() ?: return false
                return prefix in 0..32
            }

            if (addrPart.contains(':') && IPV6_CHARS.matches(addrPart)) {
                return try {
                    val bytes = parseLiteralInetAddress(addrPart).address
                    if (prefixPart == null) true
                    else {
                        val maxPrefix = bytes.size * 8
                        val prefix = prefixPart.toIntOrNull() ?: return false
                        prefix in 0..maxPrefix
                    }
                } catch (_: Exception) {
                    false
                }
            }
            return false
        }

        @JvmStatic
        fun normalizeIp(raw: String): String {
            val clean = raw.trim().substringBefore('%')
            if (!isIpAddress(clean)) return clean.lowercase(Locale.ROOT)
            if (clean.contains('/')) {
                val addrPart = clean.substringBefore('/').removeSurrounding("[", "]")
                val prefixPart = clean.substringAfter('/')
                return try {
                    val normAddr = parseLiteralInetAddress(addrPart).hostAddress.substringBefore('%').lowercase(Locale.ROOT)
                    "$normAddr/$prefixPart"
                } catch (_: Exception) {
                    clean.lowercase(Locale.ROOT)
                }
            }
            val unbracketed = clean.removeSurrounding("[", "]")
            return try {
                parseLiteralInetAddress(unbracketed).hostAddress.substringBefore('%').lowercase(Locale.ROOT)
            } catch (_: Exception) {
                unbracketed.lowercase(Locale.ROOT)
            }
        }

        @JvmStatic
        fun isIpInCidr(ip: String, cidr: String): Boolean {
            if (!isSingleIpAddress(ip) || !isIpAddress(cidr)) return false
            val slashIdx = cidr.indexOf('/')
            if (slashIdx <= 0) return false
            val netPart = cidr.substring(0, slashIdx).removeSurrounding("[", "]")
            val cleanIp = ip.trim().substringBefore('%').removeSurrounding("[", "]")
            val prefixLen = cidr.substring(slashIdx + 1).toIntOrNull() ?: return false
            return try {
                val ipBytes = parseLiteralInetAddress(cleanIp).address
                val netBytes = parseLiteralInetAddress(netPart).address
                if (ipBytes.size != netBytes.size) return false
                val maxBits = ipBytes.size * 8
                if (prefixLen < 0 || prefixLen > maxBits) return false

                val fullBytes = prefixLen / 8
                val remBits = prefixLen % 8
                for (i in 0 until fullBytes) {
                    if (ipBytes[i] != netBytes[i]) return false
                }
                if (remBits > 0) {
                    val mask = (0xFF shl (8 - remBits)) and 0xFF
                    if ((ipBytes[fullBytes].toInt() and mask) != (netBytes[fullBytes].toInt() and mask)) {
                        return false
                    }
                }
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private data class ListDto(
        val players: List<String?>? = emptyList(),
        val ips: List<String?>? = emptyList()
    )
}
