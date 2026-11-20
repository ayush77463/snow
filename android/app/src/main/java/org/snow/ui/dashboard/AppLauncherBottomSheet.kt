package org.snow.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import org.snow.R

/**
 * Friendly named-app bottom sheet for initiating allowlisted Windows desktop applications
 * or authorized owner custom executable paths on the paired Windows PC.
 */
class AppLauncherBottomSheet(
    private val onAppSelected: (target: String, friendlyName: String) -> Unit
) : BottomSheetDialogFragment() {

    data class WindowsAppItem(val friendlyName: String, val target: String)

    companion object {
        const val TAG = "AppLauncherBottomSheet"

        val ALLOWLISTED_WINDOWS_APPS = listOf(
            WindowsAppItem("VS Code", "code"),
            WindowsAppItem("Windows Terminal", "wt"),
            WindowsAppItem("Notepad", "notepad"),
            WindowsAppItem("Calculator", "calc"),
            WindowsAppItem("File Explorer", "explorer"),
            WindowsAppItem("Task Manager", "taskmgr"),
            WindowsAppItem("Paint", "mspaint"),
            WindowsAppItem("Google Chrome", "chrome"),
            WindowsAppItem("Microsoft Edge", "msedge"),
            WindowsAppItem("PowerShell", "powershell")
        )
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.bottom_sheet_app_launcher, container, false)
        val listView = root.findViewById<ListView>(R.id.app_list_view)
        val etCustomTarget = root.findViewById<EditText>(R.id.et_custom_target)
        val btnLaunchCustom = root.findViewById<Button>(R.id.btn_launch_custom)

        val adapter = object : ArrayAdapter<WindowsAppItem>(
            requireContext(),
            android.R.layout.simple_list_item_2,
            android.R.id.text1,
            ALLOWLISTED_WINDOWS_APPS
        ) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = super.getView(position, convertView, parent)
                val text1 = view.findViewById<TextView>(android.R.id.text1)
                val text2 = view.findViewById<TextView>(android.R.id.text2)
                val item = getItem(position)
                if (item != null) {
                    text1.text = item.friendlyName
                    text2.text = "Target: ${item.target}"
                }
                return view
            }
        }

        listView.adapter = adapter
        listView.setOnItemClickListener { _, _, position, _ ->
            val selected = ALLOWLISTED_WINDOWS_APPS[position]
            onAppSelected(selected.target, selected.friendlyName)
            dismiss()
        }

        btnLaunchCustom.setOnClickListener {
            val custom = etCustomTarget.text?.toString()?.trim() ?: ""
            if (custom.isBlank()) {
                Toast.makeText(requireContext(), "Please enter an executable path or target", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            onAppSelected(custom, "Custom ($custom)")
            dismiss()
        }

        return root
    }
}
