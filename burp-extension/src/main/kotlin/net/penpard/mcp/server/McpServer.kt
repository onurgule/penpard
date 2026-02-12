package net.penpard.mcp.server

import burp.api.montoya.MontoyaApi
import fi.iki.elonen.NanoHTTPD
import kotlinx.serialization.json.*
import net.penpard.mcp.tools.ToolRegistry
import java.io.InputStream
import java.util.UUID
import kotlin.concurrent.thread
import java.util.Collections

data class AuthSession(var name: String, var headers: String)

/**
 * Robust MCP HTTP Server supporting both Streamable HTTP (v2024-11-05) and Legacy SSE.
 */
class McpServer(
    private val api: MontoyaApi,
    host: String?,
    private val port: Int
) : NanoHTTPD(host, port) {

    // Configuration
    var authEnabled: Boolean = false
    var authHeaderName: String = "X-PenPard-Auth"
    var authHeaderValue: String = ""
    var isLegacySse: Boolean = false // Legacy configuration flag (UI driven)
    
    // Upstream Proxy (for tools to route through Burp)
    var upstreamProxyHost: String = "127.0.0.1"
    var upstreamProxyPort: Int = 8080
    
    // Global Auth Sessions (Managed by UI)
    val authSessions = Collections.synchronizedList(mutableListOf<AuthSession>())

    private val toolRegistry = ToolRegistry(api, this)
    private val json = Json { ignoreUnknownKeys = true; isLenient = true; encodeDefaults = true }

    override fun start() {
        try {
            start(NanoHTTPD.SOCKET_READ_TIMEOUT, false)
            api.logging().logToOutput("MCP Server started on port $port")
            if (authEnabled) api.logging().logToOutput("Auth: $authHeaderName")
        } catch (e: Exception) {
            api.logging().logToError("Failed to start MCP server: ${e.message}")
            throw e
        }
    }

    override fun stop() {
        super.stop()
        api.logging().logToOutput("MCP Server stopped")
    }

    override fun serve(session: IHTTPSession): Response {
        val uri = session.uri ?: "/"
        
        // Log basic info
        api.logging().logToOutput("${session.method} $uri")

        // 1. CORS & Preflight
        val corsHeaders = buildCorsHeaders(session)
        if (session.method == Method.OPTIONS) {
            val resp = newFixedLengthResponse(Response.Status.OK, MIME_PLAINTEXT, "")
            corsHeaders.forEach { (k, v) -> resp.addHeader(k, v) }
            return resp
        }

        // 2. Auth Check (Skip for health/oauth)
        if (authEnabled && !uri.startsWith("/health") && !uri.contains("oauth")) {
            val incoming = session.headers[authHeaderName.lowercase()]
            if (incoming == null || incoming != authHeaderValue) {
                return newJsonFixedLengthResponse(Response.Status.UNAUTHORIZED, """{"error":"Unauthorized"}""", corsHeaders)
            }
        }

        return try {
            when {
                // Determine Transport & Handler
                
                // Streamable HTTP: Main endpoint for all RPC traffic (POST only)
                uri == "/mcp" || uri == "/" -> {
                    if (session.method != Method.POST) 
                        return newJsonFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, """{"error":"Use POST"}""", corsHeaders)
                    handleStreamableMcp(session, corsHeaders)
                }

                // Universal SSE Endpoint (Hybrid)
                // POST -> Streamable HTTP (JSON) - Fixes Cursor trying POST /sse first
                // GET -> Legacy SSE (Stream) - Fallback for older clients
                uri.startsWith("/sse") -> {
                    if (session.method == Method.POST) {
                        handleStreamableMcp(session, corsHeaders)
                    } else if (session.method == Method.GET) {
                        handleLegacySse(session, corsHeaders)
                    } else {
                        newJsonFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, """{"error":"Method not allowed"}""", corsHeaders)
                    }
                }

                // Legacy Message Endpoint (POST)
                uri.startsWith("/message") -> {
                    if (session.method != Method.POST)
                         return newJsonFixedLengthResponse(Response.Status.METHOD_NOT_ALLOWED, """{"error":"Use POST"}""", corsHeaders)
                    handleLegacyMessage(session, corsHeaders)
                }

                // Health
                uri.startsWith("/health") -> {
                    newJsonFixedLengthResponse(Response.Status.OK, """{"status":"ok","mode":"${if(isLegacySse) "Legacy" else "Streamable"}"}""", corsHeaders)
                }
                
                // OAuth Discovery -> Deterministic 404
                uri.contains("oauth") -> {
                     newJsonFixedLengthResponse(Response.Status.NOT_FOUND, """{"error":"OAuth not supported"}""", corsHeaders)
                }

                else -> newJsonFixedLengthResponse(Response.Status.NOT_FOUND, """{"error":"Not Found"}""", corsHeaders)
            }
        } catch (e: Exception) {
            api.logging().logToError("Error: ${e.message}")
            e.printStackTrace()
             newJsonFixedLengthResponse(Response.Status.INTERNAL_ERROR, """{"error":"Internal Error"}""", corsHeaders)
        }
    }

    // --- STREAMABLE HTTP HANDLER (/mcp) ---
    private fun handleStreamableMcp(session: IHTTPSession, corsHeaders: Map<String, String>): Response {
        val body = readBody(session)
        if (body.isBlank()) return newJsonFixedLengthResponse(Response.Status.BAD_REQUEST, """{"error":"Empty body"}""", corsHeaders)

        api.logging().logToOutput("Streamable Request Body: $body")

        val responseJson = processJsonRpc(body, isLegacy = false)
        
        // Pass session ID back if generated
        val response = newJsonFixedLengthResponse(Response.Status.OK, responseJson, corsHeaders)
        // If we generated a session ID internally, sending it in header keeps statelessness illusion
        val sessId = UUID.randomUUID().toString()
        response.addHeader("X-Session-Id", sessId) 
        
        return response
    }

    // --- LEGACY SSE HANDLER (/sse) ---
    private fun handleLegacySse(session: IHTTPSession, corsHeaders: Map<String, String>): Response {
        val sessionId = UUID.randomUUID().toString()
        api.logging().logToOutput("Legacy SSE Start: $sessionId")

        val sseStream = SseEventInputStream()
        // Absolute Endpoint URL for maximum compatibility
        val endpointUrl = "http://127.0.0.1:$port/message?sessionId=$sessionId"
        
        // Thread to push initialization events
        thread(start = true, isDaemon = true) {
            try {
                // Wait briefly for connection to stabilize
                Thread.sleep(200)
                
                // 1. Endpoint Event
                sseStream.push(": ok\n\n".toByteArray())
                sseStream.push("event: endpoint\n".toByteArray())
                sseStream.push("data: $endpointUrl\n\n".toByteArray())
                
                // 2. Keep-Alive Loop
                while (true) {
                    Thread.sleep(15000)
                    sseStream.push(": keepalive\n\n".toByteArray())
                }
            } catch (e: Exception) {}
        }
        
        val response = newChunkedResponse(Response.Status.OK, "text/event-stream; charset=UTF-8", sseStream)
        corsHeaders.forEach { (k, v) -> response.addHeader(k, v) }
        response.addHeader("Cache-Control", "no-cache")
        response.addHeader("Connection", "keep-alive")
        response.addHeader("X-Content-Type-Options", "nosniff")
        return response
    }

    // --- LEGACY MESSAGE HANDLER (/message) ---
    private fun handleLegacyMessage(session: IHTTPSession, corsHeaders: Map<String, String>): Response {
        val body = readBody(session)
        val responseJson = processJsonRpc(body, isLegacy = true)
        return newJsonFixedLengthResponse(Response.Status.OK, responseJson, corsHeaders)
    }

    // --- CORE LOGIC ---
    private fun processJsonRpc(body: String, isLegacy: Boolean): String {
        try {
            val jsonReq = json.parseToJsonElement(body).jsonObject
            val id = jsonReq["id"] ?: JsonPrimitive(-1)
            val method = jsonReq["method"]?.jsonPrimitive?.content ?: ""
            val params = jsonReq["params"]

            return when (method) {
                "initialize" -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", id)
                    put("result", buildJsonObject {
                        put("protocolVersion", "2024-11-05") // Use Standard
                        put("capabilities", buildJsonObject {
                            put("tools", buildJsonObject { put("listChanged", false) })
                            put("logging", buildJsonObject {}) // Minimal
                            // Do not advertise others to avoid missing method errors
                        })
                        put("serverInfo", buildJsonObject {
                            put("name", "PenPard MCP Connect")
                            put("version", "1.0.0")
                        })
                    })
                }.toString()

                "notifications/initialized" -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("method", "notifications/initialized")
                }.toString()

                "ping" -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", id)
                    put("result", buildJsonObject {})
                }.toString()

                "tools/list" -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", id)
                    put("result", buildJsonObject {
                        put("tools", toolRegistry.listToolsAsJson())
                    })
                }.toString()

                "tools/call" -> {
                    val name = params?.jsonObject?.get("name")?.jsonPrimitive?.content
                    val args = params?.jsonObject?.get("arguments")?.jsonObject
                    val res = if (name != null) toolRegistry.callToolAsJson(name, args) 
                              else buildJsonObject { put("error", "Missing name") }
                    
                    buildJsonObject {
                        put("jsonrpc", "2.0")
                        put("id", id)
                        put("result", res)
                    }.toString()
                }

                // If logging/setLevel is requested because we advertised it
                "logging/setLevel" -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", id)
                    put("result", buildJsonObject {})
                }.toString()

                else -> buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", id)
                    put("error", buildJsonObject {
                        put("code", -32601)
                        put("message", "Method not found: $method")
                    })
                }.toString()
            }
        } catch (e: Exception) {
            return """{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse Error"},"id":null}"""
        }
    }

    // --- UTILS ---
    private fun readBody(session: IHTTPSession): String {
        val len = session.headers["content-length"]?.toIntOrNull() ?: 0
        return if (len > 0) {
            val buf = ByteArray(len)
            session.inputStream.read(buf, 0, len)
            String(buf)
        } else {
             val map = HashMap<String, String>()
             try { session.parseBody(map) } catch (e: Exception) {}
             map["postData"] ?: ""
        }
    }

    private fun buildCorsHeaders(session: IHTTPSession): MutableMap<String, String> {
        val origin = session.headers["origin"]
        val map = mutableMapOf(
            "Access-Control-Allow-Methods" to "GET, POST, OPTIONS",
            "Access-Control-Max-Age" to "86400",
             // Allow critical headers including session headers
            "Access-Control-Allow-Headers" to "Content-Type, Authorization, X-PenPard-Auth, X-Session-Id, MCP-Protocol-Version, Mcp-Session-Id",
            "Access-Control-Expose-Headers" to "X-Session-Id, Mcp-Session-Id"
        )
        
        if (origin != null && origin.isNotBlank()) {
            map["Access-Control-Allow-Origin"] = origin
            map["Access-Control-Allow-Credentials"] = "true"
            map["Vary"] = "Origin"
        } else {
            // Permissive fallback for non-browser clients (Electron/Node)
            map["Access-Control-Allow-Origin"] = "*"
            map["Access-Control-Allow-Credentials"] = "true" 
        }
        return map
    }

    private fun newJsonFixedLengthResponse(status: Response.IStatus, json: String, headers: Map<String, String>): Response {
        val resp = newFixedLengthResponse(status, "application/json", json)
        headers.forEach { (k, v) -> resp.addHeader(k, v) }
        return resp
    }
    
    // SSE InputStream
    class SseEventInputStream : InputStream() {
        private val queue = java.util.concurrent.LinkedBlockingQueue<Int>()
        fun push(data: ByteArray) { for (b in data) queue.offer(b.toInt() and 0xFF) }
        override fun read(): Int = try { queue.take() } catch (e: Exception) { -1 }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val c = read()
            if (c == -1) return -1
            b[off] = c.toByte()
            var i = 1
            while (i < len) {
                val next = queue.poll() ?: break
                b[off + i] = next.toByte()
                i++
            }
            return i
        }
    }
}
