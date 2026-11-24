package org.snow.ui.files

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.FragmentFilesBinding
import org.snow.network.ConnectionState
import org.snow.ui.PcFileItem
import java.util.Locale

class FilesFragment : Fragment() {

    private var _binding: FragmentFilesBinding? = null
    private val binding get() = _binding!!

    private val viewModel: FilesViewModel by activityViewModels()
    private lateinit var adapter: PcFileAdapter

    private val safFolderPickerLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
            if (uri != null) {
                val ok = viewModel.persistDestinationUri(uri)
                if (ok) {
                    binding.tvSafDestination.text = viewModel.getDestinationDisplayName()
                    Toast.makeText(requireContext(), "Download folder updated", Toast.LENGTH_SHORT).show()
                }
            }
        }

    private val sendFilePickerLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri != null) {
                handleSendFileUri(uri)
            }
        }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentFilesBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupRecyclerView()
        setupListeners()
        observeViewModel()

        binding.tvSafDestination.text = viewModel.getDestinationDisplayName()
        if (viewModel.currentPath.value.isEmpty()) {
            viewModel.loadDirectory("")
        }
    }

    private fun setupRecyclerView() {
        adapter = PcFileAdapter(
            onItemClick = { item ->
                if (item.isDirectory) {
                    viewModel.loadDirectory(item.path)
                } else {
                    promptDownloadFile(item)
                }
            }
        )
        binding.rvPcFiles.layoutManager = LinearLayoutManager(requireContext())
        binding.rvPcFiles.adapter = adapter
    }

    private fun setupListeners() {
        // Subtab Navigation
        binding.chipSubtabFiles.setOnClickListener { switchSubtab("files") }
        binding.chipSubtabApps.setOnClickListener { switchSubtab("apps") }
        binding.chipSubtabMedia.setOnClickListener { switchSubtab("media") }
        binding.chipSubtabTerminal.setOnClickListener {
            switchSubtab("terminal")
            val dialog = org.snow.ui.terminal.TerminalBottomSheetDialog()
            dialog.show(parentFragmentManager, org.snow.ui.terminal.TerminalBottomSheetDialog.TAG)
        }

        // Setup Quick Apps ListView from Allowlisted Windows Applications
        val allowlistedApps = org.snow.ui.dashboard.AppLauncherBottomSheet.ALLOWLISTED_WINDOWS_APPS
        val appDisplayNames = allowlistedApps.map { "${it.friendlyName} (${it.target})" }
        binding.lvQuickApps.adapter = android.widget.ArrayAdapter(
            requireContext(),
            android.R.layout.simple_list_item_1,
            appDisplayNames
        )
        binding.lvQuickApps.setOnItemClickListener { _, _, position, _ ->
            val app = allowlistedApps[position]
            Toast.makeText(requireContext(), "Launching ${app.friendlyName}...", Toast.LENGTH_SHORT).show()
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).launchWindowsApp(app.target) { success, err ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "${app.friendlyName} launched successfully", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), err ?: "Failed launching ${app.friendlyName}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        binding.btnLaunchAppPicker.setOnClickListener {
            val sheet = org.snow.ui.dashboard.AppLauncherBottomSheet { target, friendlyName ->
                Toast.makeText(requireContext(), "Launching $friendlyName...", Toast.LENGTH_SHORT).show()
                org.snow.ui.SnowUiRepository.getInstance(requireContext()).launchWindowsApp(target) { success, err ->
                    activity?.runOnUiThread {
                        if (success) {
                            Toast.makeText(requireContext(), "$friendlyName launched successfully", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(requireContext(), err ?: "Failed to launch $friendlyName", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
            sheet.show(parentFragmentManager, org.snow.ui.dashboard.AppLauncherBottomSheet.TAG)
        }

        // Functional Media Subtab Controls
        fun handleMediaResult(actionName: String, success: Boolean, err: String?) {
            activity?.runOnUiThread {
                if (success) {
                    binding.tvMediaStatus.text = "Playback: Sent $actionName command."
                    Toast.makeText(requireContext(), "$actionName successful", Toast.LENGTH_SHORT).show()
                } else {
                    binding.tvMediaStatus.text = "Error: ${err ?: "Command failed"}"
                    Toast.makeText(requireContext(), "Media failed: $err", Toast.LENGTH_SHORT).show()
                }
            }
        }

        binding.btnMediaPrev.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("previous") { success, err ->
                handleMediaResult("Previous Track", success, err)
            }
        }
        binding.btnMediaPlayPause.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("play_pause") { success, err ->
                handleMediaResult("Play/Pause", success, err)
            }
        }
        binding.btnMediaNext.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("next") { success, err ->
                handleMediaResult("Next Track", success, err)
            }
        }
        binding.btnMediaVolDown.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("volume_down") { success, err ->
                handleMediaResult("Volume Down", success, err)
            }
        }
        binding.btnMediaVolUp.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("volume_up") { success, err ->
                handleMediaResult("Volume Up", success, err)
            }
        }
        binding.btnMediaMute.setOnClickListener {
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).sendMediaKey("volume_mute") { success, err ->
                handleMediaResult("Mute", success, err)
            }
        }

        binding.btnMediaShareScreen.setOnClickListener {
            Toast.makeText(requireContext(), "Requesting screen share...", Toast.LENGTH_SHORT).show()
            (activity as? org.snow.ui.MainActivity)?.let { act ->
                val projMgr = act.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
                projMgr?.createScreenCaptureIntent()?.let { act.startActivity(it) }
            }
        }

        binding.btnMediaCameraPhoto.setOnClickListener {
            Toast.makeText(requireContext(), "Triggering camera capture...", Toast.LENGTH_SHORT).show()
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).triggerCameraCapture { success, err ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Camera photo captured successfully", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Camera error: $err", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        binding.btnOpenTerminalConsole.setOnClickListener {
            val dialog = org.snow.ui.terminal.TerminalBottomSheetDialog()
            dialog.show(parentFragmentManager, org.snow.ui.terminal.TerminalBottomSheetDialog.TAG)
        }

        binding.btnNavUp.setOnClickListener {
            viewModel.navigateUp()
        }

        binding.btnRefreshFiles.setOnClickListener {
            viewModel.loadDirectory(viewModel.currentPath.value)
        }

        binding.switchHideHidden.setOnCheckedChangeListener { _, isChecked ->
            viewModel.setHideHidden(isChecked)
        }

        binding.btnChangeSafFolder.setOnClickListener {
            safFolderPickerLauncher.launch(null)
        }

        binding.btnSendFileToPc.setOnClickListener {
            sendFilePickerLauncher.launch(arrayOf("*/*"))
        }

        binding.btnOpenTerminal.setOnClickListener {
            val dialog = org.snow.ui.terminal.TerminalBottomSheetDialog()
            dialog.show(parentFragmentManager, org.snow.ui.terminal.TerminalBottomSheetDialog.TAG)
        }

        // Quick jump chips
        binding.chipCDrive.setOnClickListener { viewModel.loadDirectory("C:\\") }
        binding.chipDDrive.setOnClickListener { viewModel.loadDirectory("D:\\") }
        binding.chipDesktop.setOnClickListener { viewModel.loadDirectory("Desktop") }
        binding.chipDownloads.setOnClickListener { viewModel.loadDirectory("Downloads") }
        binding.chipDocuments.setOnClickListener { viewModel.loadDirectory("Documents") }
    }

    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.connectionState.collectLatest { state ->
                if (state != ConnectionState.CONNECTED) {
                    binding.tvFilesEmpty.visibility = View.VISIBLE
                    binding.tvFilesEmpty.text = "Desktop disconnected. Connect in Devices tab to browse files."
                    adapter.submitList(emptyList())
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.currentPath.collectLatest { path ->
                binding.tvCurrentPath.text = if (path.isEmpty()) "Root" else path
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.fileItems.collectLatest { items ->
                val visible = if (viewModel.hideHidden.value) items.filterNot { it.isHidden } else items
                adapter.submitList(visible)
                if (visible.isEmpty() && viewModel.connectionState.value == ConnectionState.CONNECTED) {
                    binding.tvFilesEmpty.visibility = View.VISIBLE
                    binding.tvFilesEmpty.text = "This folder is empty."
                } else {
                    binding.tvFilesEmpty.visibility = View.GONE
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.isLoading.collectLatest { loading ->
                binding.pbFilesLoading.visibility = if (loading) View.VISIBLE else View.GONE
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.errorMessage.collectLatest { err ->
                if (err != null) {
                    Toast.makeText(requireContext(), err, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun promptDownloadFile(item: PcFileItem) {
        val sizeFormatted = formatFileSize(item.size)
        AlertDialog.Builder(requireContext())
            .setTitle("Download Remote File?")
            .setMessage("File: ${item.name}\nSize: $sizeFormatted\nDestination: ${viewModel.getDestinationDisplayName()}\n\nDownload file to phone?")
            .setPositiveButton("Download") { dialog, _ ->
                dialog.dismiss()
                Toast.makeText(requireContext(), "Starting download: ${item.name}", Toast.LENGTH_SHORT).show()
                viewModel.startDownload(item) { success, errOrPath ->
                    activity?.runOnUiThread {
                        if (success) {
                            Toast.makeText(requireContext(), "Saved to $errOrPath", Toast.LENGTH_LONG).show()
                        } else {
                            Toast.makeText(requireContext(), "Download failed: $errOrPath", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    private fun formatFileSize(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
        val pre = "KMGTPE"[exp - 1]
        return String.format(Locale.getDefault(), "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
    }

    private fun handleSendFileUri(uri: Uri) {
        var fileName = "upload_file"
        var fileSize = 0L

        try {
            val cursor = requireContext().contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = it.getColumnIndex(android.provider.OpenableColumns.SIZE)
                    if (nameIndex != -1) {
                        fileName = it.getString(nameIndex) ?: fileName
                    }
                    if (sizeIndex != -1) {
                        fileSize = it.getLong(sizeIndex)
                    }
                }
            }
        } catch (_: Exception) {
            // Use fallback defaults
        }

        AlertDialog.Builder(requireContext())
            .setTitle("Send File to PC")
            .setMessage("Upload '$fileName' (${formatFileSize(fileSize)}) to the connected PC?")
            .setPositiveButton("Upload") { _, _ ->
                viewModel.uploadFileUri(uri, fileName, fileSize) { success, errOrName ->
                    activity?.runOnUiThread {
                        if (success) {
                            Toast.makeText(requireContext(), "Upload complete: $errOrName", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(requireContext(), "Upload failed: $errOrName", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    fun switchSubtab(subtab: String) {
        if (_binding == null) return
        binding.containerSubtabFiles.visibility = if (subtab == "files") View.VISIBLE else View.GONE
        binding.containerSubtabApps.visibility = if (subtab == "apps") View.VISIBLE else View.GONE
        binding.containerSubtabMedia.visibility = if (subtab == "media") View.VISIBLE else View.GONE
        binding.containerSubtabTerminal.visibility = if (subtab == "terminal") View.VISIBLE else View.GONE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    class PcFileAdapter(
        private val onItemClick: (PcFileItem) -> Unit
    ) : RecyclerView.Adapter<PcFileAdapter.ViewHolder>() {

        private var items: List<PcFileItem> = emptyList()

        fun submitList(newItems: List<PcFileItem>) {
            items = newItems
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_pc_file, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(items[position], onItemClick)
        }

        override fun getItemCount(): Int = items.size

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            private val imgIcon: ImageView = view.findViewById(R.id.imgFileIcon)
            private val tvName: TextView = view.findViewById(R.id.tvFileName)
            private val tvMeta: TextView = view.findViewById(R.id.tvFileMeta)
            private val imgAction: ImageView = view.findViewById(R.id.imgActionIcon)

            fun bind(item: PcFileItem, onClick: (PcFileItem) -> Unit) {
                tvName.text = item.name
                if (item.isDirectory) {
                    imgIcon.setImageResource(R.drawable.ic_pc_folder)
                    tvMeta.text = "Folder"
                    imgAction.visibility = View.GONE
                } else {
                    imgIcon.setImageResource(R.drawable.ic_pc_file)
                    tvMeta.text = formatFileSize(item.size)
                    imgAction.visibility = View.VISIBLE
                    imgAction.setImageResource(R.drawable.ic_pc_download)
                }

                itemView.setOnClickListener { onClick(item) }
            }

            private fun formatFileSize(bytes: Long): String {
                if (bytes < 1024) return "$bytes B"
                val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
                val pre = "KMGTPE"[exp - 1]
                return String.format(Locale.getDefault(), "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
            }
        }
    }
}
