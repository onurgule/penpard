package net.penpard.mcp.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import javax.swing.JMenuItem
import javax.swing.JOptionPane

/**
 * Context menu: "Send to PenPard" on HTTP request. Sends the raw request to PenPard backend
 * so the user can start a test from the app (pending queue).
 */
class SendToPenPardContextMenu(private val api: MontoyaApi) : ContextMenuItemsProvider {

    override fun provideMenuItems(contextMenuEvent: ContextMenuEvent): List<Component> {
        // Prefer selection from table (Proxy history, etc.); fallback to message editor (Repeater, request panel)
        val requestResponses = contextMenuEvent.selectedRequestResponses()
        val messageEditor = contextMenuEvent.messageEditorRequestResponse()

        val requestToSend = when {
            requestResponses.isNotEmpty() -> requestResponses.first().request().toString()
            messageEditor.isPresent -> messageEditor.get().requestResponse().request().toString()
            else -> null
        }
        if (requestToSend.isNullOrBlank()) return emptyList()

        val rawRequest = requestToSend
        val item = JMenuItem("Send to PenPard")
        item.addActionListener {
            val prefs = api.persistence().preferences()
            val baseUrl = prefs.getString("penpard_backend_url")?.trim() ?: "http://127.0.0.1:4000"
            val token = prefs.getString("penpard_send_token")?.trim()
            sendToBackend(baseUrl, token, rawRequest)
        }
        return listOf(item)
    }

    private fun sendToBackend(baseUrl: String, token: String?, rawRequest: String) {
        try {
            val url = URL("$baseUrl/api/penpard/send-request")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            if (!token.isNullOrBlank()) {
                conn.setRequestProperty("X-PenPard-Send-Token", token)
            }
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            val body = """{"rawRequest":${escapeJson(rawRequest)}}"""
            conn.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            val code = conn.responseCode
            if (code in 200..299) {
                api.logging().logToOutput("Send to PenPard: request queued successfully.")
                JOptionPane.showMessageDialog(null, "Request sent to PenPard.\nOpen PenPard to start the test.", "Send to PenPard", JOptionPane.INFORMATION_MESSAGE)
            } else {
                val err = conn.errorStream?.readBytes()?.toString(StandardCharsets.UTF_8) ?: "Unknown error"
                api.logging().logToError("Send to PenPard failed: $code - $err")
                JOptionPane.showMessageDialog(null, "Failed to send to PenPard: $code\n$err", "Send to PenPard", JOptionPane.ERROR_MESSAGE)
            }
        } catch (e: Exception) {
            api.logging().logToError("Send to PenPard error: ${e.message}")
            JOptionPane.showMessageDialog(null, "Error: ${e.message}\nIs PenPard backend running at $baseUrl?", "Send to PenPard", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun escapeJson(s: String): String {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""
    }
}
