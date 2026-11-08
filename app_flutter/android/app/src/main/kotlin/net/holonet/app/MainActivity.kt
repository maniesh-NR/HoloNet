// MainActivity — Flutter host + Material You dynamic color bridge.
// Exposes the platform's Monet palette (Android 12+) over the
// "dynamiccolor" MethodChannel so the Dart engine renders true
// wallpaper-derived Material You.
package net.holonet.app

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val vpnRequest = 0xF01
    private val channel = "net.holonet.app/dynamiccolor"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Material You on Android: wallpaper-derived colors are provided by
        // the system; Flutter's engine handles them natively when the theme
        // is dynamic — the channel exposes the resolved scheme explicitly so
        // the HoloNet color engine stays consistent across platforms.
        MethodChannel(flutterEngine!!.dartExecutor.binaryMessenger, channel).setMethodCallHandler { call, result ->
            when (call.method) {
                "dark", "light" -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        val dark = call.method == "dark"
                        val res = if (dark) android.R.style.ThemeOverlay_Material3_Dark else android.R.style.ThemeOverlay_Material3_Light
                        val themed = themeContext(res)
                        val roles = mapOf(
                            "primary" to themed.getColor(android.R.attr.colorPrimary),
                            "onPrimary" to themed.getColor(android.R.attr.colorOnPrimary),
                            "primaryContainer" to themed.getColor(android.R.attr.colorPrimaryContainer),
                            "onPrimaryContainer" to themed.getColor(android.R.attr.colorOnPrimaryContainer),
                            "secondary" to themed.getColor(android.R.attr.colorSecondary),
                            "onSecondary" to themed.getColor(android.R.attr.colorOnSecondary),
                            "tertiary" to themed.getColor(android.R.attr.colorTertiary),
                            "onTertiary" to themed.getColor(android.R.attr.colorOnTertiary),
                            "error" to themed.getColor(android.R.attr.colorError),
                            "onError" to themed.getColor(android.R.attr.colorOnError),
                            "surface" to themed.getColor(android.R.attr.colorSurface),
                            "onSurface" to themed.getColor(android.R.attr.colorOnSurface),
                            "surfaceContainerHighest" to themed.getColor(android.R.attr.colorSurfaceContainerHighest),
                            "outline" to themed.getColor(android.R.attr.colorOutline),
                            "outlineVariant" to themed.getColor(android.R.attr.colorOutlineVariant),
                            "inverseSurface" to themed.getColor(android.R.attr.colorSurfaceInverse),
                            "onInverseSurface" to themed.getColor(android.R.attr.colorOnSurfaceInverse)
                        )
                        result.success(roles)
                    } else {
                        result.success(null) // below Android 12: seeded scheme
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun themeContext(styleRes: Int): android.content.Context {
        return object : android.content.ContextThemeWrapper(this, styleRes) {}
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        // VPN consent granted → start HoloVpnService (foreground).
    }
}
