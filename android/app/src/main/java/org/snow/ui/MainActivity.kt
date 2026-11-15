package org.snow.ui

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.ActivityMainBinding
import org.snow.network.ConnectionState
import org.snow.protocol.Constants
import org.snow.service.SnowForegroundService

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var service: SnowForegroundService? = null
    private var isBound = false

    private var stateJob: Job? = null
    private var logsJob: Job? = null

    private val requestNotificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                appendLog("Notification permission granted.")
            } else {
                appendLog("Warning: Notification permission denied. Background notifications may not be shown.")
            }
        }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? SnowForegroundService.LocalBinder
            service = localBinder?.service
            isBound = true
            observeService()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
            isBound = false
            cleanupObservers()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        checkNotificationPermission()
        setupListeners()
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, SnowForegroundService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        cleanupObservers()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun setupListeners() {
        binding.btnConnect.setOnClickListener {
            val host = binding.editHost.text?.toString()?.trim() ?: ""
            val portStr = binding.editPort.text?.toString()?.trim() ?: ""

            if (host.isEmpty()) {
                Toast.makeText(this, "Please enter desktop IP address", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull()
            if (port == null || port !in 1..65535) {
                Toast.makeText(this, "Invalid port number (1-65535)", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            SnowForegroundService.startConnect(this, host, port)
            appendLog("Initiating connection to $host:$port ...")
        }

        binding.btnDisconnect.setOnClickListener {
            SnowForegroundService.stop(this)
            appendLog("Disconnect requested.")
        }

        binding.btnPing.setOnClickListener {
            service?.client?.sendRequest("ping") { response ->
                runOnUiThread {
                    appendLog("Ping reply received! Payload: ${response.payload}")
                }
            } ?: run {
                Toast.makeText(this, "Not connected", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnClearLog.setOnClickListener {
            binding.tvLog.text = ""
        }
    }

    private fun observeService() {
        val currentService = service ?: return
        cleanupObservers()

        stateJob = lifecycleScope.launch {
            currentService.client.connectionState.collectLatest { state ->
                updateUiForState(state)
            }
        }

        logsJob = lifecycleScope.launch {
            currentService.client.logs.collectLatest { logLine ->
                appendLog(logLine)
            }
        }
    }

    private fun cleanupObservers() {
        stateJob?.cancel()
        stateJob = null
        logsJob?.cancel()
        logsJob = null
    }

    private fun updateUiForState(state: ConnectionState) {
        binding.tvStatus.text = state.name

        when (state) {
            ConnectionState.DISCONNECTED -> {
                binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected))
                binding.btnConnect.isEnabled = true
                binding.btnDisconnect.isEnabled = false
                binding.btnPing.isEnabled = false
            }
            ConnectionState.CONNECTING -> {
                binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_connecting))
                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.isEnabled = false
            }
            ConnectionState.CONNECTED -> {
                binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_connected))
                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.isEnabled = true
            }
            ConnectionState.RECONNECTING -> {
                binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.status_reconnecting))
                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.isEnabled = false
            }
        }
    }

    private fun appendLog(line: String) {
        binding.tvLog.append("$line\n")
        binding.scrollLog.post {
            binding.scrollLog.fullScroll(android.view.View.FOCUS_DOWN)
        }
    }
}
