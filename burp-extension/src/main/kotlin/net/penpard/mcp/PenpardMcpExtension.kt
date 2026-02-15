package net.penpard.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.InterceptedRequest
import net.penpard.mcp.server.McpServer
import net.penpard.mcp.ui.PenpardTab
import net.penpard.mcp.ui.SendToPenPardContextMenu
import net.penpard.mcp.server.AuthSession
import kotlinx.serialization.json.*
import kotlinx.serialization.decodeFromString

/**
 * PenPard MCP Connect - Burp Suite Extension
 * 
 * Provides an MCP SSE server that listens on all interfaces,
 * allowing external clients to connect and perform scans.
 * 
 * Also registers a Proxy handler to annotate and highlight
 * PenPard Agent requests in Burp HTTP History.
 */
class PenpardMcpExtension : BurpExtension {
    
    private lateinit var api: MontoyaApi
    private var mcpServer: McpServer? = null
    
    companion object {
        const val EXTENSION_NAME = "PenPard MCP Connect"
        const val DEFAULT_PORT = 9876
        const val DEFAULT_HOST = "0.0.0.0"
        const val PENPARD_HEADER = "X-PenPard-Agent"
        const val PENPARD_ANNOTATION = "[PenPard]"
    }
    
    override fun initialize(api: MontoyaApi) {
        this.api = api
        
        api.extension().setName(EXTENSION_NAME)
        
        // ── Register Proxy Handler for PenPard request annotation ──
        // Detects X-PenPard-Agent header, annotates in HTTP History, strips before forwarding
        api.proxy().registerRequestHandler(PenPardProxyRequestHandler(api))
        api.logging().logToOutput("PenPard Proxy Handler registered - agent requests will be annotated in HTTP History")
        
        // Load initial preferences
        val prefs = api.persistence().preferences()
        val port = prefs.getString("mcp_port")?.toIntOrNull() ?: DEFAULT_PORT
        val authEnabled = prefs.getBoolean("mcp_auth_enabled") ?: false
        val authHeader = prefs.getString("mcp_auth_header") ?: "X-PenPard-Auth"
        val authValue = prefs.getString("mcp_auth_value") ?: ""
        val isLegacySse = prefs.getBoolean("mcp_legacy_sse") ?: false
        val proxyHost = prefs.getString("mcp_proxy_host") ?: "127.0.0.1"
        val proxyPort = prefs.getString("mcp_proxy_port")?.toIntOrNull() ?: 8080
        
        val sessionsJson = prefs.getString("mcp_auth_sessions") ?: "[]"
        val sessions = try {
             val json = Json { ignoreUnknownKeys = true }
             json.decodeFromString<List<Map<String, String>>>(sessionsJson).map { 
                 AuthSession(it["name"] ?: "Unknown", it["headers"] ?: "") 
             }
        } catch (e: Exception) { emptyList() }
        
        // Start Server initially
        startServer(port, authEnabled, authHeader, authValue, isLegacySse, proxyHost, proxyPort, sessions)
        
        // Helper callback for UI restart
        val restartServerCallback: (Int, Boolean, String, String, Boolean, String, Int, List<AuthSession>) -> Boolean = 
            { newPort, newAuth, newHeader, newValue, newLegacy, newProxyHost, newProxyPort, newSessions ->
                stopServer()
                startServer(newPort, newAuth, newHeader, newValue, newLegacy, newProxyHost, newProxyPort, newSessions)
            }
        
        // Register UI Tab
        val tab = PenpardTab(api, restartServerCallback)
        api.userInterface().registerSuiteTab("PenPard", tab.getUiComponent())

        // Context menu: Send to PenPard (sends selected request to backend pending queue)
        api.userInterface().registerContextMenuItemsProvider(SendToPenPardContextMenu(api))
        
        // Register unload handler
        api.extension().registerUnloadingHandler {
            stopServer()
            api.logging().logToOutput("$EXTENSION_NAME unloaded")
        }
    }
    
    /**
     * Proxy Request Handler that detects PenPard Agent requests,
     * annotates them in HTTP History with a highlight + comment,
     * and strips the internal header before forwarding to the target.
     *
     * This ensures:
     * - PenPard requests are clearly visible in Burp HTTP History
     * - PenPard requests bypass Intercept (never held) 
     * - The internal header is never sent to the target server
     */
    private class PenPardProxyRequestHandler(private val api: MontoyaApi) : ProxyRequestHandler {
        
        override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
            if (interceptedRequest.hasHeader(PENPARD_HEADER)) {
                // Strip the internal header so target never sees it
                val cleanRequest = interceptedRequest.withRemovedHeader(PENPARD_HEADER)
                // Annotate: comment + cyan highlight for easy visual identification
                val annotations = Annotations.annotations(
                    "$PENPARD_ANNOTATION Agent Request",
                    HighlightColor.CYAN
                )
                // doNotIntercept → PenPard requests never block in Intercept tab
                return ProxyRequestReceivedAction.doNotIntercept(cleanRequest, annotations)
            }
            // User requests pass through normally
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }
        
        override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }
    }
    
    private fun startServer(port: Int, authEnabled: Boolean, authHeader: String, authValue: String, isLegacySse: Boolean, proxyHost: String, proxyPort: Int, sessions: List<AuthSession>): Boolean {
        return try {
            api.logging().logToOutput("$EXTENSION_NAME starting on port $port...")
            
            mcpServer = McpServer(api, DEFAULT_HOST, port).apply {
                this.authEnabled = authEnabled
                this.authHeaderName = authHeader
                this.authHeaderValue = authValue
                this.isLegacySse = isLegacySse
                this.upstreamProxyHost = proxyHost
                this.upstreamProxyPort = proxyPort
                this.authSessions.clear()
                this.authSessions.addAll(sessions)
                start()
            }
            true
        } catch (e: Exception) {
            api.logging().logToError("Failed to start MCP server: ${e.message}")
            false
        }
    }
    
    private fun stopServer() {
        mcpServer?.stop()
        mcpServer = null
    }
}
