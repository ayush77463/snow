package org.snow.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.DialogApprovalsBottomSheetBinding
import java.util.Locale

class ApprovalsBottomSheetDialog : BottomSheetDialogFragment() {

    private var _binding: DialogApprovalsBottomSheetBinding? = null
    private val binding get() = _binding!!

    private val repository by lazy { SnowUiRepository.getInstance(requireContext()) }

    companion object {
        const val TAG = "ApprovalsBottomSheetDialog"
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = DialogApprovalsBottomSheetBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupListeners()
        observeApprovals()
        refreshApprovals()
    }

    private fun setupListeners() {
        binding.btnSheetRefreshApprovals.setOnClickListener {
            refreshApprovals()
        }
    }

    private fun refreshApprovals() {
        repository.fetchPendingApprovals { res ->
            res.onSuccess { renderItems(it) }.onFailure { renderItems(emptyList()) }
        }
    }

    private fun observeApprovals() {
        viewLifecycleOwner.lifecycleScope.launch {
            repository.pendingApprovalsCount.collectLatest { count ->
                binding.tvSheetApprovalsCount.text = count.toString()
            }
        }
    }

    private fun renderItems(list: List<PendingApprovalItem>?) {
        activity?.runOnUiThread {
            if (_binding == null) return@runOnUiThread
            if (list.isNullOrEmpty()) {
                binding.tvSheetApprovalsEmpty.visibility = View.VISIBLE
                binding.nsvApprovalsItems.visibility = View.GONE
                binding.layoutSheetApprovalsItems.removeAllViews()
            } else {
                binding.tvSheetApprovalsEmpty.visibility = View.GONE
                binding.nsvApprovalsItems.visibility = View.VISIBLE
                binding.layoutSheetApprovalsItems.removeAllViews()

                val inflater = LayoutInflater.from(requireContext())
                for (item in list) {
                    val itemView = inflater.inflate(R.layout.item_pending_approval, binding.layoutSheetApprovalsItems, false)
                    val tvOp = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_op)
                    val tvRisk = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_risk)
                    val tvPrincipal = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_principal)
                    val tvReason = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_reason)
                    val tvTtl = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_ttl)
                    val btnApprove = itemView.findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_approve)
                    val btnDeny = itemView.findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_deny)

                    tvOp.text = item.action
                    tvRisk.text = item.riskLevel.uppercase(Locale.US)
                    tvPrincipal.text = "Caller: ${item.principal} • Target: ${item.targetDevice}"
                    tvReason.text = item.reason
                    val remSec = item.timeRemainingSeconds.toInt()
                    tvTtl.text = if (remSec > 0) "⏳ ${remSec}s remaining" else "⛔ Expired"

                    btnApprove.setOnClickListener {
                        btnApprove.isEnabled = false
                        btnDeny.isEnabled = false
                        repository.resolveApproval(item.requestId, "APPROVE") { res ->
                            activity?.runOnUiThread {
                                res.onSuccess {
                                    Toast.makeText(requireContext(), "Approved request ${item.action} 🛡️", Toast.LENGTH_SHORT).show()
                                    refreshApprovals()
                                }.onFailure { err ->
                                    Toast.makeText(requireContext(), "Approval failed: ${err.message}", Toast.LENGTH_SHORT).show()
                                    btnApprove.isEnabled = true
                                    btnDeny.isEnabled = true
                                }
                            }
                        }
                    }

                    btnDeny.setOnClickListener {
                        btnApprove.isEnabled = false
                        btnDeny.isEnabled = false
                        repository.resolveApproval(item.requestId, "DENY") { res ->
                            activity?.runOnUiThread {
                                res.onSuccess {
                                    Toast.makeText(requireContext(), "Denied request ${item.action}", Toast.LENGTH_SHORT).show()
                                    refreshApprovals()
                                }.onFailure { err ->
                                    Toast.makeText(requireContext(), "Deny failed: ${err.message}", Toast.LENGTH_SHORT).show()
                                    btnApprove.isEnabled = true
                                    btnDeny.isEnabled = true
                                }
                            }
                        }
                    }

                    binding.layoutSheetApprovalsItems.addView(itemView)
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
