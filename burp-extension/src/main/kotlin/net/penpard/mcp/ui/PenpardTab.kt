package net.penpard.mcp.ui

import burp.api.montoya.MontoyaApi
import net.penpard.mcp.server.AuthSession
import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Dimension
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.table.DefaultTableModel
import kotlinx.serialization.json.*
import kotlinx.serialization.encodeToString

/**
 * UI Tab for PenPard MCP Configuration
 */
class PenpardTab(
    private val api: MontoyaApi,
    private val onRestartServer: (Int, Boolean, String, String, Boolean, String, Int, List<AuthSession>) -> Boolean
) {
    private val panel = JPanel(GridBagLayout())
    
    // UI Components
    private val portField = JTextField("9876", 5)
    private val legacyRadioButton = JRadioButton("Legacy SSE")
    private val streamableRadioButton = JRadioButton("Streamable HTTP", true) 
    private val transportGroup = ButtonGroup()
    
    // Proxy Components
    private val proxyHostField = JTextField("127.0.0.1", 15)
    private val proxyPortField = JTextField("8080", 5)
    
    // Auth Components
    private val authCheckBox = JCheckBox("Enable Authentication Header")
    private val headerNameField = JTextField("X-PenPard-Auth", 15)
    private val headerValueField = JTextField("", 15)

    // Send to PenPard (context menu)
    private val backendUrlField = JTextField("http://127.0.0.1:4000", 25)
    private val sendTokenField = JTextField("", 20)
    
    // Session Components
    private val sessionsModel = DefaultTableModel(arrayOf("Name", "Headers"), 0)
    private val sessionsTable = JTable(sessionsModel)
    
    private val statusLabel = JLabel("Status: Running")
    private val extensionInfo = JLabel("MCP Endpoint: http://0.0.0.0:9876/sse")

    init {
        transportGroup.add(legacyRadioButton)
        transportGroup.add(streamableRadioButton)
        
        setupUI()
        loadPreferences()
        
        updateAuthFieldsState()
        authCheckBox.addActionListener { updateAuthFieldsState() }
    }

    fun getUiComponent(): Component {
        return JScrollPane(panel) // Scrollable for smaller screens
    }

    private fun setupUI() {
        panel.border = EmptyBorder(20, 20, 20, 20)
        val gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        // Title
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        val titleLabel = JLabel("PenPard MCP Connect Settings")
        titleLabel.font = titleLabel.font.deriveFont(16f).deriveFont(java.awt.Font.BOLD)
        panel.add(titleLabel, gbc)

        // Server Port
        gbc.gridy++
        gbc.gridwidth = 1
        panel.add(JLabel("Server Port:"), gbc)
        gbc.gridx = 1
        panel.add(portField, gbc)
        
        // Transport Mode
        gbc.gridx = 0
        gbc.gridy++
        panel.add(JLabel("Transport Mode:"), gbc)
        gbc.gridx = 1
        val radioPanel = JPanel()
        radioPanel.add(streamableRadioButton)
        radioPanel.add(legacyRadioButton)
        panel.add(radioPanel, gbc)

        // Upstream Proxy
        gbc.gridx = 0
        gbc.gridy++
        gbc.gridwidth = 2
        panel.add(JSeparator(), gbc)
        
        gbc.gridy++
        val proxyLabel = JLabel("Upstream Proxy (Chain to Burp)")
        proxyLabel.font = proxyLabel.font.deriveFont(java.awt.Font.BOLD)
        panel.add(proxyLabel, gbc)
        
        gbc.gridy++
        gbc.gridwidth = 1
        panel.add(JLabel("Proxy Host:"), gbc)
        gbc.gridx = 1
        panel.add(proxyHostField, gbc)
        
        gbc.gridx = 0
        gbc.gridy++
        panel.add(JLabel("Proxy Port:"), gbc)
        gbc.gridx = 1
        panel.add(proxyPortField, gbc)

        // Send to PenPard (right-click context menu)
        gbc.gridx = 0
        gbc.gridy++
        gbc.gridwidth = 2
        panel.add(JSeparator(), gbc)
        gbc.gridy++
        val sendLabel = JLabel("Send to PenPard (context menu)")
        sendLabel.font = sendLabel.font.deriveFont(java.awt.Font.BOLD)
        panel.add(sendLabel, gbc)
        gbc.gridy++
        gbc.gridwidth = 1
        panel.add(JLabel("PenPard backend URL:"), gbc)
        gbc.gridx = 1
        panel.add(backendUrlField, gbc)
        gbc.gridx = 0
        gbc.gridy++
        panel.add(JLabel("Token (optional):"), gbc)
        gbc.gridx = 1
        panel.add(sendTokenField, gbc)
        gbc.gridx = 0

        // Authentication
        gbc.gridy++
        gbc.gridwidth = 2
        panel.add(JSeparator(), gbc)

        gbc.gridy++
        panel.add(authCheckBox, gbc)

        // Header Name
        gbc.gridy++
        gbc.gridwidth = 1
        panel.add(JLabel("Header Name:"), gbc)
        gbc.gridx = 1
        panel.add(headerNameField, gbc)

        // Header Value
        gbc.gridx = 0
        gbc.gridy++
        panel.add(JLabel("Header Value:"), gbc)
        gbc.gridx = 1
        panel.add(headerValueField, gbc)
        
        // --- Sessions Management ---
        gbc.gridx = 0
        gbc.gridy++
        gbc.gridwidth = 2
        panel.add(JSeparator(), gbc)
        
        gbc.gridy++
        val sessionLabel = JLabel("Auth Analyzer Sessions (IDOR Automation)")
        sessionLabel.font = sessionLabel.font.deriveFont(java.awt.Font.BOLD)
        panel.add(sessionLabel, gbc)
        
        gbc.gridy++
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 1.0 // Allow table to expand
        gbc.weightx = 1.0
        val tableScroll = JScrollPane(sessionsTable)
        tableScroll.preferredSize = Dimension(400, 150)
        panel.add(tableScroll, gbc)
        
        gbc.gridy++
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weighty = 0.0
        
        val btnPanel = JPanel()
        val addBtn = JButton("Add Session")
        val removeBtn = JButton("Remove Selected")
        
        addBtn.addActionListener { addSessionDialog() }
        removeBtn.addActionListener { 
            val row = sessionsTable.selectedRow
            if (row != -1) sessionsModel.removeRow(row)
        }
        
        btnPanel.add(addBtn)
        btnPanel.add(removeBtn)
        panel.add(btnPanel, gbc)

        // Save & Restart Button
        gbc.gridy++
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        
        val restartButton = JButton("Save Configuration & Restart Server")
        restartButton.addActionListener { handleRestart() }
        panel.add(restartButton, gbc)
        
        // Status Area
        gbc.gridy++
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST
        statusLabel.foreground = java.awt.Color(0, 128, 0)
        panel.add(statusLabel, gbc)
        
        gbc.gridy++
        panel.add(extensionInfo, gbc)
    }
    
    private fun addSessionDialog() {
        val nameField = JTextField(10)
        val headersArea = JTextArea(5, 20)
        val msgPanel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints()
        gbc.gridx=0; gbc.gridy=0; gbc.anchor=GridBagConstraints.WEST
        msgPanel.add(JLabel("Session Name (e.g. Admin):"), gbc)
        gbc.gridy++; msgPanel.add(nameField, gbc)
        gbc.gridy++; msgPanel.add(JLabel("Headers (e.g. Cookie: a=b):"), gbc)
        gbc.gridy++; msgPanel.add(JScrollPane(headersArea), gbc)
        
        val res = JOptionPane.showConfirmDialog(panel, msgPanel, "Add Auth Session", JOptionPane.OK_CANCEL_OPTION)
        if (res == JOptionPane.OK_OPTION && nameField.text.isNotBlank()) {
            sessionsModel.addRow(arrayOf(nameField.text, headersArea.text))
        }
    }

    private fun updateAuthFieldsState() {
        val enabled = authCheckBox.isSelected
        headerNameField.isEnabled = enabled
        headerValueField.isEnabled = enabled
    }

    private fun loadPreferences() {
        val prefs = api.persistence().preferences()
        portField.text = prefs.getString("mcp_port") ?: "9876"
        authCheckBox.isSelected = prefs.getBoolean("mcp_auth_enabled") ?: false
        headerNameField.text = prefs.getString("mcp_auth_header") ?: "X-PenPard-Auth"
        headerValueField.text = prefs.getString("mcp_auth_value") ?: ""
        
        proxyHostField.text = prefs.getString("mcp_proxy_host") ?: "127.0.0.1"
        proxyPortField.text = prefs.getString("mcp_proxy_port") ?: "8080"
        backendUrlField.text = prefs.getString("penpard_backend_url") ?: "http://127.0.0.1:4000"
        sendTokenField.text = prefs.getString("penpard_send_token") ?: ""

        val isLegacy = prefs.getBoolean("mcp_legacy_sse") ?: false
        if (isLegacy) legacyRadioButton.isSelected = true else streamableRadioButton.isSelected = true
        
        // Load Sessions
        val sessionsJson = prefs.getString("mcp_auth_sessions") ?: "[]"
        try {
             val json = Json { ignoreUnknownKeys = true }
             val sessions = json.decodeFromString<List<Map<String, String>>>(sessionsJson) // Store as simple list of maps for persistence
             sessionsModel.rowCount = 0
             sessions.forEach { 
                 sessionsModel.addRow(arrayOf(it["name"], it["headers"]))
             }
        } catch (e: Exception) {}

        updateAuthFieldsState()
        updateStatusLabel()
    }
    
    private fun savePreferences() {
        val prefs = api.persistence().preferences()
        prefs.setString("mcp_port", portField.text)
        prefs.setBoolean("mcp_auth_enabled", authCheckBox.isSelected)
        prefs.setString("mcp_auth_header", headerNameField.text)
        prefs.setString("mcp_auth_value", headerValueField.text)
        prefs.setBoolean("mcp_legacy_sse", legacyRadioButton.isSelected)
        
        prefs.setString("mcp_proxy_host", proxyHostField.text)
        prefs.setString("mcp_proxy_port", proxyPortField.text)
        prefs.setString("penpard_backend_url", backendUrlField.text)
        prefs.setString("penpard_send_token", sendTokenField.text)

        // Save Sessions
        val sessions = mutableListOf<Map<String, String>>()
        for (i in 0 until sessionsModel.rowCount) {
            sessions.add(mapOf(
                "name" to (sessionsModel.getValueAt(i, 0) as String),
                "headers" to (sessionsModel.getValueAt(i, 1) as String)
            ))
        }
        val json = Json { encodeDefaults = true }
        prefs.setString("mcp_auth_sessions", json.encodeToString(sessions))
    }

    private fun handleRestart() {
        try {
            val port = portField.text.toInt()
            val auth = authCheckBox.isSelected
            val headerIdx = headerNameField.text
            val headerVal = headerValueField.text
            val pHost = proxyHostField.text
            val pPort = proxyPortField.text.toInt()
            
            // Build AuthSession List
            val sessionList = mutableListOf<AuthSession>()
            for (i in 0 until sessionsModel.rowCount) {
                sessionList.add(AuthSession(
                    name = sessionsModel.getValueAt(i, 0) as String,
                    headers = sessionsModel.getValueAt(i, 1) as String
                ))
            }
            
            if (auth && (headerIdx.isBlank() || headerVal.isBlank())) {
                JOptionPane.showMessageDialog(panel, "Header Name and Value cannot be empty when Auth is enabled.", "Validation Error", JOptionPane.ERROR_MESSAGE)
                return
            }

            statusLabel.text = "Status: Restarting..."
            statusLabel.foreground = java.awt.Color.ORANGE
            
            val success = onRestartServer(port, auth, headerIdx, headerVal, legacyRadioButton.isSelected, pHost, pPort, sessionList)
            
            if (success) {
                savePreferences()
                statusLabel.text = "Status: Running on port $port"
                statusLabel.foreground = java.awt.Color(0, 128, 0)
                extensionInfo.text = "MCP Endpoint: http://0.0.0.0:$port/sse"
                JOptionPane.showMessageDialog(panel, "Server restarted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
            } else {
                statusLabel.text = "Status: Error starting server"
                statusLabel.foreground = java.awt.Color.RED
                JOptionPane.showMessageDialog(panel, "Failed to start server. Check Burp Extensions > Output tab for details.", "Error", JOptionPane.ERROR_MESSAGE)
            }
        } catch (e: NumberFormatException) {
            JOptionPane.showMessageDialog(panel, "Invalid Port Number", "Error", JOptionPane.ERROR_MESSAGE)
        }
    }
    
    private fun updateStatusLabel() {
        // Initializes with running state since extension starts automatically
        val port = portField.text
        statusLabel.text = "Status: Running on port $port"
        extensionInfo.text = "MCP Endpoint: http://0.0.0.0:$port/sse"
    }
}
