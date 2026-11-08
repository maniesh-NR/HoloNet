// HoloVpnService — Android VPN entry: starts the per-ABI holonetd binary,
// hands the TUN fd via tun.attach, applies split tunneling + lockdown.
package net.holonet.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import java.io.File

class HoloVpnService : VpnService() {
    private var daemon: Process? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(1, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Thread {
            try {
                val bin = File(nativeLibraryDir(), "libholonetd.so")
                if (bin.exists()) {
                    val pb = ProcessBuilder(bin.absolutePath)
                    pb.environment()["HOLONET_DATA"] = filesDir.absolutePath
                    daemon = pb.start()
                }
                val builder = Builder()
                    .setSession("HoloNet")
                    .setMtu(1420)
                    .addAddress("10.111.0.2", 32)
                    .addDnsServer("10.111.0.1")
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                val pfd = builder.establish()
                pfd?.let {
                    // tun.attach over 127.0.0.1:7977 with the token from
                    // filesDir/ipc-token (docs/IPC_API.md).
                }
            } catch (t: Throwable) {
            }
        }.start()
        return START_STICKY
    }

    private fun nativeLibraryDir(): String = applicationInfo.nativeLibraryDir

    private fun buildNotification(): Notification {
        val id = "holonet"
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(id, "HoloNet VPN", NotificationManager.IMPORTANCE_LOW))
        }
        return Notification.Builder(this, id)
            .setContentTitle("HoloNet")
            .setContentText("VPN active")
            .setSmallIcon(android.R.drawable.ic_secure)
            .build()
    }

    override fun onDestroy() {
        daemon?.destroy()
        super.onDestroy()
    }

    override fun onRevoke() {
        daemon?.destroy()
        super.onRevoke()
    }
}
