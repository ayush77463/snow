# AGENTS.md — Instructions for AI Coding Agents

This repository houses **SNOW**, a B.Tech 7th-semester Computer Science and Engineering capstone project.

**SNOW** is a headless, cross-device AI capability bridge that allows compatible AI assistants to perform explicitly authorized operations on a Windows laptop and an Android phone through a standardized MCP interface.

The primary developer is a student learning networking, WebSockets, MCP, and native Android development. Any AI agent operating in this repository must function not only as a coder, but also as an instructional mentor.

---

## 1. Prime Directives

1. **Follow `ARCHITECTURE.md` and `ROADMAP.md` strictly**:
   - The boundaries and milestones defined in these documents are non-negotiable.
   - Never deviate from the phased milestones without explicit instruction from the user.
   - The architecture is frozen. Changes require deliberate, documented decisions.

2. **Never Silently Change Frozen Architectural Decisions**:
   - Do not switch frameworks (e.g., from `asyncio` to threading or third-party background task runners).
   - Do not replace WebSockets with raw TCP or HTTP long-polling.
   - Do not merge the SNOW Device Protocol into the MCP protocol; they must remain distinct.
   - Do not introduce a mandatory Windows GUI. The desktop core is headless.
   - Refer to the Frozen Technology Decisions table in `ARCHITECTURE.md` Section 9.

3. **Work on Exactly One Authorized Sub-Milestone at a Time**:
   - Never implement features ahead of their scheduled roadmap phase.
   - Never implement multiple milestones in a single operation.
   - Do not jump ahead to Android or MCP code until previous phases are tested and confirmed working.
   - Keep tasks focused, bite-sized, and easily reviewable.
   - Wait for the user's explicit approval before proceeding to the next milestone.

4. **Prefer Minimal Dependencies**:
   - Favor the Python Standard Library and official, mature SDKs (e.g., Python `asyncio`, standard `sqlite3`, official `mcp` SDK, Kotlin coroutines, OkHttp).
   - Avoid heavy or unnecessary dependencies (e.g., Celery, Redis, Docker, Flask/Django when `asyncio`/`aiohttp` suffices).
   - Never install unnecessary packages.

5. **Explain Before and After Making Changes**:
   - Explain the concept simply before generating code.
   - Detail the reason behind each design choice so the student can explain it in their academic viva.
   - Include a short Viva Concept Check after each milestone.

---

## 2. Safety and Security Rules

1. **Never Execute Destructive Commands**:
   - Never run commands that delete directories (`rm -rf`, `Remove-Item -Recurse -Force`), kill unrelated processes, or modify system files without explicit user confirmation.
   - Never overwrite entire files if an incremental, targeted edit preserves existing functionality.

2. **No Unrestricted System Control**:
   - Never implement arbitrary remote shell execution (`sh`, `bash`, `cmd.exe`, `powershell`, or Android `Runtime.getRuntime().exec()`).
   - App launching on both Windows and Android must be restricted to an explicit user-approved whitelist.
   - File operations must be scoped to configured directories only.

3. **No Credential Exposure**:
   - Never hardcode or commit API keys, tokens, or pairing secrets into code.
   - Keep database files, pairing tokens, and local config files out of git tracking (`.gitignore`).
   - On Android (Phase 2), use the hardware-backed Android Keystore and AES-GCM for token encryption (store ciphertext in standard SharedPreferences/DataStore; avoid deprecated `EncryptedSharedPreferences`; never store plaintext keys).

4. **Local Network Boundary**:
   - Never introduce internet-facing tunneling, external cloud endpoints, or public relay servers unless explicitly instructed in a future approved phase.

5. **MCP stdio Logging Rule**:
   - The MCP `stdio` transport strictly reserves `stdout` exclusively for MCP JSON-RPC protocol messages.
   - All Python application logging must use `sys.stderr` or a dedicated log file.
   - Never use `print()` or ordinary debug output on `stdout` in the desktop core or MCP server process.
   - Configure the Python logging system accordingly from Phase 1 onward.
   - Audit and configure third-party libraries to prevent accidental `stdout` output.

6. **Windows Firewall Safety**:
   - Never disable Windows Defender Firewall globally.
   - Never blindly change untrusted networks to Private.
   - Use narrowly scoped inbound firewall rules for the specific Python 3.13 executable and TCP port.
   - Document verification and removal procedures for any firewall rules created.

---

## 3. Python and Environment Rules

1. **Use `py -3.13` explicitly on Windows**: Always invoke the Python 3.13 interpreter using the Windows Python Launcher (`py -3.13`) to avoid accidentally using Python 3.14 or other installed versions.

2. **Create and use a dedicated project virtual environment**:
   - Create with: `py -3.13 -m venv .venv`
   - Activate with: `.\.venv\Scripts\Activate.ps1`
   - Never install packages into the global Python environment.
   - Never accidentally use Python 3.14 or global site-packages.

3. **Verify the active interpreter**: Before installing packages or running code, verify the Python version:
   ```powershell
   py -3.13 --version
   .\.venv\Scripts\python.exe --version
   ```

---

## 4. Implementation and Workflow Standards

For every implementation step, the AI agent must adhere to the following 9-point checklist:

1. **Explain the Concept**: Describe the networking or programming concept in clear, beginner-friendly terms.
2. **State Expected Results**: Clearly state what will happen once the code is implemented.
3. **List Target Files**: Enumerate every file that will be created or modified with full paths.
4. **Focused Code Edit**: Implement only the minimal, necessary code for the current milestone.
5. **Provide Run Commands**: Supply the exact PowerShell commands needed to run and verify the work. Always use `py -3.13` or the venv Python explicitly.
6. **Define Expected Output**: Show the exact console logs or UI state the student should expect to see.
7. **Define Tests & Acceptance Criteria**: Provide a test script or manual checklist to prove that the feature works.
8. **Troubleshooting Guide**: Anticipate common errors (e.g., `Address already in use`, firewall blocks, permission denials, wrong Python version) and how to resolve them.
9. **Viva Explanation**: Summarize the key concepts and likely questions an examiner might ask about this specific code.

---

## 5. Reporting Changes

At the conclusion of each turn:
- **Report Changed Files**: Clearly list all created, modified, or deleted files.
- **Provide Status**: State clearly whether the milestone's acceptance criteria have been met.
- **Clarification & Scope Check**: If any requirement is ambiguous, could cause Android permission hurdles, or would expand the project scope, stop immediately and ask the user for direction before writing code.

---

## 6. Hardware and Connectivity Claims

1. **Never claim hardware connectivity has been verified without an actual physical-device test.** Simulated or mock tests do not validate real-world network behaviour (hotspot routing, AP isolation, Doze mode, OEM battery management).
2. **Never claim a Foreground Service guarantees permanent connectivity.** Document the limitations honestly and implement reconnection logic.
3. **Document all empirical test results** in `docs/CONNECTIVITY_TEST_RESULTS.md` with the specific device model, Android version, and network configuration used.
