// Main.kt — HoloNet macOS frontend (Compose Multiplatform), fully Material
// You: the shared Kotlin port of holo-theme drives a Compose Material 3
// theme from the user's seed; the daemon's `theme.get`/`settings.set` keep
// the seed in sync with the Flutter and Qt frontends.
package net.holonet.app

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.InetSocketAddress
import java.net.Socket

// ---------------------------------------------------------------------------
// IPC (NDJSON JSON-RPC 2.0 — docs/IPC_API.md)
// ---------------------------------------------------------------------------

class HoloIpc {
    private var socket: Socket? = null
    private var writer: PrintWriter? = null
    private var reader: BufferedReader? = null
    private var nextId = 100

    fun connect(token: String, port: Int = 7977): Boolean = try {
        socket = Socket().apply { connect(InetSocketAddress("127.0.0.1", port), 5000) }
        writer = PrintWriter(socket!!.getOutputStream(), true)
        reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
        request("hello", """{"token":"$token"}""") != null
    } catch (t: Throwable) { false }

    fun request(method: String, paramsJson: String = "{}"): String? = try {
        val id = nextId++
        writer?.println("""{"jsonrpc":"2.0","id":$id,"method":"$method","params":$paramsJson}""")
        var line = reader?.readLine() ?: return null
        while (line.contains("\"method\":\"event\"")) line = reader?.readLine() ?: return null
        line
    } catch (t: Throwable) { null }

    fun close() { try { socket?.close() } catch (_: Throwable) {} }
}

// ---------------------------------------------------------------------------
// Material You state (seed persisted via the daemon; local fallback)
// ---------------------------------------------------------------------------

private const val DATA_DIR_SUFFIX = "/Library/Application Support/HoloNet"
private val SEED_PRESETS = listOf("#6750A4", "#B3261E", "#0061A4", "#006E1C", "#7D5260", "#8C4E00", "#984061", "#3F6978")

fun main() {
    val dataDir = System.getProperty("user.home") + DATA_DIR_SUFFIX
    File(dataDir).mkdirs()
    val token = File("$dataDir/ipc-token").let { if (it.exists()) it.readText().trim() else "" }
    val ipc = HoloIpc()
    val connected = token.isNotEmpty() && ipc.connect(token)

    application {
        var osDark by remember { mutableStateOf(System.getProperty("apple.awt.UIElement") == null && isOsDark(dataDir)) }
        var themeMode by remember { mutableStateOf("system") }
        var seedHex by remember { mutableStateOf("#6750A4") }
        var dynamicColor by remember { mutableStateOf(true) }

        // Load the authoritative settings from the daemon.
        LaunchedEffect(connected) {
            if (connected) {
                val st = ipc.request("theme.get", """{"osTheme":"${if (osDark) "dark" else "light"}"}""")
                st?.let {
                    val seed = Regex(""""_seed":"(#[0-9a-fA-F]{6})"""").find(it)?.groupValues?.get(1)
                    val mode = Regex(""""_mode":"(\w+)"""").find(it)?.groupValues?.get(1)
                    if (seed != null) seedHex = seed
                    if (mode != null) themeMode = mode
                    val dynamic = Regex("""\\"_dynamic\\":\\"(true|false)\\"""").find(it)?.groupValues?.get(1)
                    if (dynamic != null) dynamicColor = dynamic == "true"
                }
            }
        }

        val dark = when (themeMode) { "dark" -> true; "light" -> false; else -> osDark }
        val seed = Argb.fromHex(seedHex) ?: Argb.DEFAULT
        val scheme = MaterialYouScheme.fromSeed(seed, if (dark) MaterialYouMode.DARK else MaterialYouMode.LIGHT)

        Window(onCloseRequest = { ipc.close(); exitApplication() }, title = "HoloNet") {
            HoloNetApp(
                scheme = scheme,
                dark = dark,
                seedHex = seedHex,
                themeMode = themeMode,
                dynamicColor = dynamicColor,
                onSeedChange = { hex ->
                    seedHex = hex
                    if (connected) {
                        ipc.request("settings.set", """{"values":{"seed_color":"$hex"}}""")
                    }
                },
                onThemeModeChange = { mode ->
                    themeMode = mode
                    if (connected) {
                        ipc.request("settings.set", """{"values":{"theme_mode":"$mode"}}""")
                    }
                },
                onDynamicColorChange = { enabled ->
                    dynamicColor = enabled
                    if (connected) {
                        ipc.request("settings.set", """{"values":{"dynamic_color":"$enabled"}}""")
                    }
                },
                ipcConnected = connected,
            )
        }
    }
}

// macOS dark-mode detection (defaults read).
private fun isOsDark(dataDir: String): Boolean = try {
    val p = ProcessBuilder("defaults", "read", "-g", "AppleInterfaceStyle").start()
    p.inputStream.readBytes().toString(Charsets.UTF_8).trim().equals("Dark", ignoreCase = true)
} catch (t: Throwable) { false }

// ---------------------------------------------------------------------------
// Compose Material 3 UI from the Material You scheme
// ---------------------------------------------------------------------------

private fun Argb.toCompose() = Color(r, g, b, a)

private fun normalizeSeedHex(value: String): String? {
    val hex = value.trim().removePrefix("#")
    return if (hex.matches(Regex("[0-9a-fA-F]{6}"))) "#" + hex.uppercase() else null
}

@Composable
fun HoloNetApp(
    scheme: MaterialYouScheme,
    dark: Boolean,
    seedHex: String,
    themeMode: String,
    dynamicColor: Boolean,
    onSeedChange: (String) -> Unit,
    onThemeModeChange: (String) -> Unit,
    onDynamicColorChange: (Boolean) -> Unit,
    ipcConnected: Boolean,
) {
    val baseScheme = if (dark) darkColorScheme() else lightColorScheme()
    val cs = baseScheme.copy(
        primary = scheme.primary.toCompose(),
        onPrimary = scheme.onPrimary.toCompose(),
        primaryContainer = scheme.primaryContainer.toCompose(),
        onPrimaryContainer = scheme.onPrimaryContainer.toCompose(),
        secondary = scheme.secondary.toCompose(),
        onSecondary = scheme.onSecondary.toCompose(),
        secondaryContainer = scheme.secondaryContainer.toCompose(),
        onSecondaryContainer = scheme.onSecondaryContainer.toCompose(),
        tertiary = scheme.tertiary.toCompose(),
        onTertiary = scheme.onTertiary.toCompose(),
        tertiaryContainer = scheme.tertiaryContainer.toCompose(),
        onTertiaryContainer = scheme.onTertiaryContainer.toCompose(),
        error = scheme.error.toCompose(),
        onError = scheme.onError.toCompose(),
        errorContainer = scheme.errorContainer.toCompose(),
        onErrorContainer = scheme.onErrorContainer.toCompose(),
        background = scheme.background.toCompose(),
        onBackground = scheme.onBackground.toCompose(),
        surface = scheme.surface.toCompose(),
        onSurface = scheme.onSurface.toCompose(),
        surfaceVariant = scheme.surfaceVariant.toCompose(),
        onSurfaceVariant = scheme.onSurfaceVariant.toCompose(),
        outline = scheme.outline.toCompose(),
        outlineVariant = scheme.outlineVariant.toCompose(),
        inverseSurface = scheme.inverseSurface.toCompose(),
        inverseOnSurface = scheme.inverseOnSurface.toCompose(),
    )

    MaterialTheme(colorScheme = cs) {
        var selectedPage by remember { mutableStateOf(0) }
        var customSeed by remember(seedHex) { mutableStateOf(seedHex) }

        Row(Modifier.fillMaxSize()) {
            NavigationRail {
                NavigationRailItem(
                    selected = selectedPage == 0,
                    onClick = { selectedPage = 0 },
                    icon = { Text("⌂") },
                    label = { Text("Home") },
                    alwaysShowLabel = true,
                )
                NavigationRailItem(
                    selected = selectedPage == 1,
                    onClick = { selectedPage = 1 },
                    icon = { Text("⚙") },
                    label = { Text("Settings") },
                    alwaysShowLabel = true,
                )
            }

            Box(Modifier.weight(1f).fillMaxHeight()) {
                if (selectedPage == 0) {
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text("HoloNet", fontSize = 32.sp, fontWeight = FontWeight.Bold)
                        Text(
                            if (ipcConnected) "daemon connected · Material You" else "offline · Material You (local seed)",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(32.dp))
                        ConnectOrb(scheme)
                    }
                } else {
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp),
                    ) {
                        Text("Settings", fontSize = 28.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(20.dp))
                        Text("Appearance", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Choose how HoloNet looks. Your seed color is shared across platforms.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(20.dp))

                        Text("Theme mode", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(8.dp))
                        Row(
                            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            listOf("system" to "System", "light" to "Light", "dark" to "Dark").forEach { (mode, label) ->
                                FilterChip(
                                    selected = themeMode == mode,
                                    onClick = { onThemeModeChange(mode) },
                                    label = { Text(label) },
                                )
                            }
                        }

                        Spacer(Modifier.height(20.dp))
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text("Dynamic color", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                                Text(
                                    "Uses Android 12+ wallpaper colors when available.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            Switch(checked = dynamicColor, onCheckedChange = onDynamicColorChange)
                        }

                        Spacer(Modifier.height(24.dp))
                        Text("Seed color", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Choose a preset or enter a custom six-digit hex color.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            SEED_PRESETS.forEach { hex ->
                                val argb = Argb.fromHex(hex) ?: return@forEach
                                val selected = seedHex.equals(hex, ignoreCase = true)
                                Box(
                                    modifier = Modifier
                                        .size(42.dp)
                                        .clip(CircleShape)
                                        .background(argb.toCompose())
                                        .border(
                                            width = if (selected) 3.dp else 0.dp,
                                            color = MaterialTheme.colorScheme.primary,
                                            shape = CircleShape,
                                        )
                                        .clickable { onSeedChange(hex) },
                                )
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            val normalizedSeed = normalizeSeedHex(customSeed)
                            OutlinedTextField(
                                value = customSeed,
                                onValueChange = { customSeed = it },
                                label = { Text("Custom hex") },
                                singleLine = true,
                                isError = customSeed.isNotBlank() && normalizedSeed == null,
                                modifier = Modifier.weight(1f),
                            )
                            Button(
                                onClick = { normalizedSeed?.let(onSeedChange) },
                                enabled = normalizedSeed != null,
                            ) {
                                Text("Apply")
                            }
                        }
                        Text(
                            "Example: #6750A4. The selected seed updates HoloNet across platforms.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
@Composable
private fun ConnectOrb(scheme: MaterialYouScheme) {
    Surface(
        shape = CircleShape,
        color = scheme.primaryContainer.toCompose(),
        modifier = Modifier.size(180.dp),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("HOLO", fontSize = 26.sp, fontWeight = FontWeight.Bold, color = scheme.onPrimaryContainer.toCompose())
                Text(
                    "disconnected",
                    style = MaterialTheme.typography.labelLarge,
                    color = scheme.onPrimaryContainer.toCompose(),
                )
            }
        }
    }
}
