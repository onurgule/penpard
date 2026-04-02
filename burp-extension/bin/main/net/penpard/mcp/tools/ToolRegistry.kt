package net.penpard.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.params.HttpParameterType
import kotlinx.serialization.json.*
import net.penpard.mcp.server.McpServer
import java.util.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.InputStream
import java.io.OutputStream
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.net.ssl.HostnameVerifier
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * Registry of comprehensive MCP tools for Pentesting.
 */
class ToolRegistry(private val api: MontoyaApi, private val server: McpServer) {
    
    // Helper JSON factory
    private val jsonFactory = Json { ignoreUnknownKeys = true; isLenient = true; encodeDefaults = true }
    
    // SSL Verification Bypass (Trust-All) for Proxy Chaining
    private val sslContext by lazy {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate>? = null
            override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) {}
        })
        val sc = SSLContext.getInstance("TLS")
        sc.init(null, trustAllCerts, SecureRandom())
        sc
    }

    fun listToolsAsJson(): JsonArray {
        return buildJsonArray {
            // --- 1. CORE BURP NAVIGATION & ACTIONS ---
            addTool(this, "send_to_scanner", "Starts an active scan (audit) on a URL or raw request in Burp Scanner", 
                params("url" to "string?", "host" to "string?", "port" to "integer?", "useHttps" to "boolean?", "request" to "string?"))
                
            addTool(this, "send_to_repeater", "Sends an HTTP request to Repeater", 
                params("host" to "string", "port" to "integer", "useHttps" to "boolean", "request" to "string", "name" to "string?"))

            addTool(this, "send_to_intruder", "Sends an HTTP request to Intruder", 
                params("host" to "string", "port" to "integer", "useHttps" to "boolean", "request" to "string"))

            addTool(this, "add_to_scope", "Adds a URL to the target scope", 
                params("url" to "string"))
            
            addTool(this, "get_scope", "Lists all URLs currently in scope", params())

            // --- 2. INFORMATION GATHERING (RECON) ---
            addTool(this, "get_proxy_history", "Get Proxy history. Use excludePenPard=true to see only user requests, includeDetails=true for request/response details.", 
                params("count" to "integer?", "offset" to "integer?", "urlRegex" to "string?", "excludePenPard" to "boolean?", "includeDetails" to "boolean?"))
            
            addTool(this, "get_session_cookies", "Get Cookie header from the most recent USER request to the given host (from Burp proxy history). Use for authenticated testing when the user has logged in via browser/Burp (e.g. Google OAuth). Excludes PenPard agent requests.", 
                params("host" to "string"))
            
            addTool(this, "get_cookies_and_auth_for_host", "Get Cookie and Authorization headers from proxy history for a host, newest to oldest. Use before test to discover session/auth for target domain. Excludes PenPard requests.", 
                params("host" to "string", "maxItems" to "integer?"))
            
            addTool(this, "get_sitemap", "Get Sitemap tree urls", 
                params("prefix" to "string?"))
            
            addTool(this, "get_scanner_issues", "Get scanner issues", 
                params("count" to "integer?", "minSeverity" to "string?"))

            // --- 3. ACTIVE EXECUTION ---
            addTool(this, "send_http_request", "Issue a raw HTTP request. Set penpard_source to tag PenPard agent requests in Burp Proxy History.", 
                params("host" to "string", "port" to "integer", "useHttps" to "boolean", "request" to "string", "penpard_source" to "string?"))
            
            addTool(this, "spider_url", "Send URL to Spider", params("url" to "string"))

            // --- 4. UTILITIES (ENCODING/DECODING) ---
            addTool(this, "url_encode", "URL Encode string", params("data" to "string"))
            addTool(this, "url_decode", "URL Decode string", params("data" to "string"))
            addTool(this, "base64_encode", "Base64 Encode string", params("data" to "string"))
            addTool(this, "base64_decode", "Base64 Decode string", params("data" to "string"))
            addTool(this, "hash_data", "Hash data (MD5/SHA1/SHA256)", params("data" to "string", "algorithm" to "string"))

            // --- 5. PENTEST HELPERS (AGENT ACCELERATORS) ---
            addTool(this, "extract_links", "Extract all links/src from HTML response", params("html" to "string"))
            addTool(this, "extract_comments", "Extract HTML comments", params("html" to "string"))
            addTool(this, "generate_payloads", "Get common pentest payloads", params("type" to "string (sqli, xss, lfi)"))
            
            // New: Native Auth/IDOR Checker (Replaces Auth Analyzer for Agent)
            addTool(this, "check_authorization", "Test IDOR/Auth bypass by replaying request with different sessions", 
                params("request" to "string", "sessions" to "string (JSON Array: [{name:'User1', headers:'Cookie: ...'}])", "host" to "string", "port" to "integer", "useHttps" to "boolean"))
            
            // --- 6. ACTIVITY MONITORING ---
            addTool(this, "get_user_activity", "Analyze recent USER-only activity for Smart Assist. Requests with X-PenPard-Agent header are always excluded — assist only on real user traffic. Detects SQLi, XSS, LFI patterns.", 
                params("count" to "integer?", "sinceMinutes" to "integer?"))

            // --- 7. CONFIGURATION ---
            addTool(this, "get_burp_version", "Get Burp Suite Version", params())
            addTool(this, "enable_intercept", "Enable Proxy Intercept", params())
            addTool(this, "disable_intercept", "Disable Proxy Intercept", params())
        }
    }

    private fun addTool(arrayBuilder: JsonArrayBuilder, name: String, desc: String, props: JsonObject) {
         arrayBuilder.add(buildJsonObject {
            put("name", name)
            put("description", desc)
            put("inputSchema", buildJsonObject {
                put("type", "object")
                put("properties", props)
            })
        })
    }
    
    // Quick helper to build parameter schema
    private fun params(vararg pairs: Pair<String, String>): JsonObject {
        return buildJsonObject {
            pairs.forEach { (name, typeDesc) ->
                val isOptional = typeDesc.endsWith("?")
                val cleanType = typeDesc.removeSuffix("?")
                val cleanTypeSplit = cleanType.split(" ") // handle descriptions like "string (details)"
                val type = cleanTypeSplit[0]
                
                put(name, buildJsonObject {
                    put("type", type)
                    if (cleanTypeSplit.size > 1) {
                         put("description", cleanTypeSplit.drop(1).joinToString(" ").removePrefix("(").removeSuffix(")"))
                    }
                })
            }
        }
    }

    fun callToolAsJson(name: String, args: JsonObject?): JsonElement {
        api.logging().logToOutput("Executing Tool: $name")
        return try {
            when (name) {
                // Actions
                "send_to_scanner" -> sendToScanner(args)
                "send_to_repeater" -> sendToRepeater(args)
                "send_to_intruder" -> sendToIntruder(args)
                "send_http_request" -> sendHttpRequest(args)
                "add_to_scope" -> addToScope(args)
                "spider_url" -> spiderUrl(args)
                
                // Recon
                "get_proxy_history" -> getProxyHistory(args)
                "get_session_cookies" -> getSessionCookies(args)
                "get_cookies_and_auth_for_host" -> getCookiesAndAuthForHost(args)
                "get_sitemap" -> getSitemap(args)
                "get_scanner_issues" -> getScannerIssues(args)
                "get_scope" -> getScope()
                
                // Utils
                "url_encode" -> urlEncode(args)
                "url_decode" -> urlDecode(args)
                "base64_encode" -> base64Encode(args)
                "base64_decode" -> base64Decode(args)
                "hash_data" -> hashData(args)
                
                // Helpers
                "extract_links" -> extractLinks(args)
                "extract_comments" -> extractComments(args)
                "generate_payloads" -> generatePayloads(args)
                "check_authorization" -> checkAuthorization(args)
                
                // Activity
                "get_user_activity" -> getUserActivity(args)
                
                // Config
                "get_burp_version" -> getBurpVersion()
                "enable_intercept" -> setIntercept(true)
                "disable_intercept" -> setIntercept(false)

                else -> buildJsonObject { put("error", "Unknown tool: $name") }
            }
        } catch (e: Exception) {
            api.logging().logToError("Tool Execution Failed ($name): ${e.message}")
            buildJsonObject { put("error", e.message ?: "Unknown error") }
        }
    }

    // --- HELPERS (Inlined for robustness) ---
    // Extensions removed to prevent resolution issues.
    
    // --- UTILS for MCP Spec Compliance ---
    
    private fun success(msg: String): JsonObject {
        return buildJsonObject {
            put("content", buildJsonArray {
                add(buildJsonObject {
                    put("type", "text")
                    put("text", msg)
                })
            })
            put("isError", false) // Explicit success
        }
    }

    private fun err(msg: String): JsonObject {
        return buildJsonObject {
            put("content", buildJsonArray {
                add(buildJsonObject {
                    put("type", "text")
                    put("text", "Error: $msg")
                })
            })
            put("isError", true)
        }
    }
    
    // For tools returning complex JSON data (like proxy history), we serialize it to string 
    // and return it as a text block, as MCP tools primarily return text for LLM consumption.
    private fun jsonResult(jsonElement: JsonElement): JsonObject {
        return success(jsonElement.toString())
    }
    
    // Fix for literal escape characters in request strings from LLM
    private fun unescapeRequest(raw: String): String {
        return raw.replace("\\r", "\r")
                  .replace("\\n", "\n")
                  .replace("\\t", "\t")
    }

    // --- IMPLEMENTATIONS ---

    private fun sendToScanner(args: JsonObject?): JsonElement {
        val url = args?.get("url")?.jsonPrimitive?.content
        val host = args?.get("host")?.jsonPrimitive?.content
        val port = args?.get("port")?.jsonPrimitive?.intOrNull
        val secure = args?.get("useHttps")?.jsonPrimitive?.booleanOrNull
        val rawRequest = args?.get("request")?.jsonPrimitive?.content

        return try {
            val httpReq: HttpRequest
            val scanUrl: String

            if (host != null && rawRequest != null) {
                // Build request from raw request + host/port/https
                val p = port ?: if (secure == true) 443 else 80
                val s = secure ?: (p == 443)
                httpReq = HttpRequest.httpRequest(HttpService.httpService(host, p, s), unescapeRequest(rawRequest))
                scanUrl = "${if (s) "https" else "http"}://$host${if (p != (if (s) 443 else 80)) ":$p" else ""}"
            } else if (url != null) {
                // Build request from URL
                httpReq = HttpRequest.httpRequestFromUrl(url)
                scanUrl = url
            } else {
                return err("Provide either 'url' or 'host'+'request'")
            }

            // Add to scope so scanner can work on it
            api.scope().includeInScope(scanUrl)

            // Start active scan audit and add the request
            val auditConfig = burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(
                burp.api.montoya.scanner.BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            )
            val audit = api.scanner().startAudit(auditConfig)
            audit.addRequest(httpReq)

            success("Active scan started on: $scanUrl")
        } catch (e: Exception) {
            err("Scanner error: ${e.message}")
        }
    }

    private fun sendToRepeater(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val port = args?.get("port")?.jsonPrimitive?.intOrNull ?: 443
        val secure = args?.get("useHttps")?.jsonPrimitive?.booleanOrNull ?: true
        val request = unescapeRequest(args?.get("request")?.jsonPrimitive?.content ?: return err("Missing request"))
        val name = args?.get("name")?.jsonPrimitive?.content
        
        val httpReq = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), request)
        api.repeater().sendToRepeater(httpReq, name)
        return success("Sent to Repeater")
    }

    private fun sendToIntruder(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val port = args?.get("port")?.jsonPrimitive?.intOrNull ?: 443
        val secure = args?.get("useHttps")?.jsonPrimitive?.booleanOrNull ?: true
        val request = unescapeRequest(args?.get("request")?.jsonPrimitive?.content ?: return err("Missing request"))
        
        val httpReq = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), request)
        api.intruder().sendToIntruder(httpReq)
        return success("Sent to Intruder")
    }

    // --- IDOR / Auth Checker Implementation ---
    private fun checkAuthorization(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val port = args?.get("port")?.jsonPrimitive?.intOrNull ?: 443
        val secure = args?.get("useHttps")?.jsonPrimitive?.booleanOrNull ?: true
        val rawRequest = unescapeRequest(args?.get("request")?.jsonPrimitive?.content ?: return err("Missing request"))
        val sessionsJson = args?.get("sessions")?.jsonPrimitive?.content ?: "[]"
        
        // Prepare Session List (Args > Global UI Sessions)
        val sessionsList = mutableListOf<Pair<String, String>>()
        
        // 1. Try to parse from arguments
        if (sessionsJson != "[]" && sessionsJson.isNotBlank()) {
             try {
                val array = jsonFactory.parseToJsonElement(sessionsJson).jsonArray
                array.forEach { 
                    val obj = it.jsonObject
                    sessionsList.add(
                        (obj["name"]?.jsonPrimitive?.content ?: "Unknown") to 
                        (unescapeRequest(obj["headers"]?.jsonPrimitive?.content ?: ""))
                    )
                }
             } catch (e: Exception) {
                return err("Invalid sessions JSON. Expected: [{'name':'UserA', 'headers':'...'}, ...]")
             }
        }
        
        // 2. If no args provided, use Global UI Sessions
        if (sessionsList.isEmpty()) {
             synchronized(server.authSessions) {
                 server.authSessions.forEach {
                     sessionsList.add(it.name to unescapeRequest(it.headers))
                 }
             }
        }
        
        if (sessionsList.isEmpty()) {
            return err("No sessions provided via arguments, and no global sessions configured in PenPard tab.")
        }

        val results = buildJsonArray {
            sessionsList.forEach { (name, headersRaw) ->
                
                // Prepare Request
                val service = HttpService.httpService(host, port, secure)
                val baseReq = HttpRequest.httpRequest(service, rawRequest) // Use parsed request
                // ... (Rest of implementation same)
                
                val method = baseReq.method()
                val path = baseReq.path()
                val urlStr = "${if(secure) "https" else "http"}://$host:$port$path"
                
                // Connection with Proxy
                try {
                    val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(server.upstreamProxyHost, server.upstreamProxyPort))
                    val conn = URL(urlStr).openConnection(proxy) as HttpURLConnection
                    
                    if (conn is HttpsURLConnection) {
                        conn.sslSocketFactory = sslContext.socketFactory
                        conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
                    }
                    
                    conn.requestMethod = method
                    conn.doInput = true
                    conn.instanceFollowRedirects = false
                    
                    // Apply Headers: Base (minus Auth) + Session Headers
                    var hasContentType = false
                    baseReq.headers().forEach { h ->
                        val key = h.name()
                        // Filter out auth headers from base request
                        if (!key.equals("Cookie", ignoreCase = true) && 
                            !key.equals("Authorization", ignoreCase = true) &&
                            !key.equals("X-Csrf-Token", ignoreCase = true)) {
                            conn.addRequestProperty(key, h.value())
                            if (key.equals("Content-Type", ignoreCase = true)) hasContentType = true
                        }
                    }
                    
                    // Add Session Headers
                    headersRaw.lineSequence().forEach { line ->
                        if (line.contains(":")) {
                            val parts = line.split(":", limit = 2)
                            val k = parts[0].trim()
                            conn.addRequestProperty(k, parts[1].trim())
                            if (k.equals("Content-Type", ignoreCase = true)) hasContentType = true
                        }
                    }
                    
                    // Auto-detect JSON Content-Type
                    if (!hasContentType) {
                        val body = baseReq.bodyToString().trim()
                        if ((body.startsWith("{") && body.endsWith("}")) || (body.startsWith("[") && body.endsWith("]"))) {
                            conn.addRequestProperty("Content-Type", "application/json")
                        }
                    }
                    
                    // Body
                    if (baseReq.body().length() > 0) {
                        conn.doOutput = true
                        conn.outputStream.use { os ->
                            os.write(baseReq.body().getBytes())
                        }
                    }
                    
                    // Response
                    val status = conn.responseCode
                    val stream = if (status < 400) conn.inputStream else conn.errorStream
                    val bodyBytes = stream?.readBytes() ?: kotlin.ByteArray(0)
                    
                    add(buildJsonObject {
                        put("session", name)
                        put("status", status)
                        put("length", bodyBytes.size)
                        put("preview", String(bodyBytes.take(200).toByteArray()) + "...")
                        // Simple heuristic
                        put("access", if (status >= 200 && status < 300) "2xx" else if (status >= 400) "4xx" else "$status")
                    })
                    
                } catch (e: Exception) {
                    add(buildJsonObject {
                        put("session", name)
                        put("error", e.message)
                    })
                }
            }
        }

        return jsonResult(buildJsonObject { put("auth_results", results) })
    }

    private fun sendHttpRequest(args: JsonObject?): JsonElement {
        // Support two modes:
        // Mode 1: Full raw request with host, port, useHttps, request (raw HTTP string)
        // Mode 2: Simple request with method, url, headers, body
        
        val url = args?.get("url")?.jsonPrimitive?.content
        
        return if (url != null) {
            // Mode 2: Simple URL-based request
            sendSimpleHttpRequest(args)
        } else {
            // Mode 1: Raw request string
            sendRawHttpRequest(args)
        }
    }
    
    private fun readUntilDoubleNewline(inp: java.io.InputStream): kotlin.ByteArray {
        val buf = mutableListOf<Byte>()
        var prev = 0
        var prev2 = 0
        var prev3 = 0
        while (true) {
            val b = inp.read()
            if (b < 0) break
            buf.add(b.toByte())
            if (prev3 == '\r'.code && prev2 == '\n'.code && prev == '\r'.code && b == '\n'.code) break
            if (prev == '\n'.code && b == '\n'.code) break
            prev3 = prev2; prev2 = prev; prev = b
        }
        return buf.toByteArray()
    }

    private fun parseHttpResponse(bytes: kotlin.ByteArray): Pair<Int, kotlin.ByteArray> {
        val str = String(bytes, StandardCharsets.UTF_8)
        val crlf = str.indexOf("\r\n\r\n")
        val lf = str.indexOf("\n\n")
        val headerEnd = if (crlf >= 0) crlf else if (lf >= 0) lf else -1
        val bodyStart = headerEnd + (if (crlf >= 0) 4 else 2)
        val statusRegex = Regex("HTTP/\\d\\.\\d\\s+(\\d+)")
        val status = statusRegex.find(str)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val body = if (headerEnd >= 0 && bodyStart < bytes.size) bytes.copyOfRange(bodyStart, bytes.size) else bytes
        return Pair(status, body)
    }

    /**
     * Fixes common truncated XSS payloads (LLM sometimes sends incomplete payloads like <img src=x).
     */
    private fun fixTruncatedXssPayload(value: String): String {
        val v = value.trim()
        if (v.contains("onerror=") && v.endsWith(">")) return value
        if (v.contains("</script>")) return value
        if (v.contains("onload=") && v.endsWith(">")) return value
        if (v.endsWith("<img src=x") || v.endsWith("<img src=\"x\"") || v.endsWith("<img src='x'")) {
            return v + " onerror=alert(1)>"
        }
        if (v.endsWith("<img src=") || v.endsWith("<img src=\"")) {
            return v + "x onerror=alert(1)>"
        }
        if (v.contains("<script>") && !v.contains("</script>")) {
            return v + "alert(1)</script>"
        }
        if (v.contains("<svg") && !v.contains("onload")) {
            return v + " onload=alert(1)>"
        }
        return value
    }

    /**
     * Encodes URL query parameters for pentest payloads.
     * java.net.URL truncates/mangles URLs with unencoded spaces and special chars (e.g. ' OR 1=1--).
     * Ensures spaces -> + (application/x-www-form-urlencoded) and special chars -> %XX so Burp receives correct payloads.
     */
    private fun encodeQueryParamsForPentest(url: String): String {
        val qIdx = url.indexOf('?')
        if (qIdx < 0) return url
        val base = url.substring(0, qIdx)
        val query = url.substring(qIdx + 1)
        val encodedParams = query.split('&').joinToString("&") { param ->
            val eqIdx = param.indexOf('=')
            if (eqIdx < 0) URLEncoder.encode(param, StandardCharsets.UTF_8.name())
            else {
                val name = param.substring(0, eqIdx)
                var value = param.substring(eqIdx + 1)
                if (value.contains("<img") || value.contains("<script") || value.contains("<svg")) {
                    value = fixTruncatedXssPayload(value)
                }
                "$name=${URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
            }
        }
        return "$base?$encodedParams"
    }
    
    private fun sendSimpleHttpRequest(args: JsonObject?): JsonElement {
        val rawUrl = args?.get("url")?.jsonPrimitive?.content ?: return err("Missing url")
        // CRITICAL: Encode query params so payloads like ' OR 1=1-- and <img src=x onerror=alert(1)> are sent correctly
        val url = encodeQueryParamsForPentest(rawUrl)
        val method = args?.get("method")?.jsonPrimitive?.content ?: "GET"
        val headersJson = args?.get("headers")
        val body = args?.get("body")?.jsonPrimitive?.content ?: ""
        val useProxy = args?.get("use_proxy")?.jsonPrimitive?.booleanOrNull ?: true
        
        return try {
            // Parse ONLY the base URL (before ?) - java.net.URL truncates query at = and other chars!
            val qIdx = url.indexOf('?')
            val baseUrl = if (qIdx >= 0) url.substring(0, qIdx) else url
            val encodedQuery = if (qIdx >= 0) url.substring(qIdx + 1) else null
            val parsedBase = java.net.URL(baseUrl)
            val host = parsedBase.host
            val secure = parsedBase.protocol == "https"
            val port = if (parsedBase.port != -1) parsedBase.port else if (secure) 443 else 80
            val path = (if (parsedBase.path.isNullOrEmpty()) "/" else parsedBase.path) + (if (encodedQuery != null) "?$encodedQuery" else "")
            
            // Build raw HTTP request
            val rawRequest = StringBuilder()
            rawRequest.append("$method $path HTTP/1.1\r\n")
            rawRequest.append("Host: $host\r\n")
            
            // Inject PenPard Agent header if present (tags requests in Burp Proxy History)
            val penpardSource = args?.get("penpard_source")?.jsonPrimitive?.content
            if (penpardSource != null) {
                rawRequest.append("X-PenPard-Agent: $penpardSource\r\n")
            }
            
            // Add custom headers (skip Host/Connection — already set above; skip X-PenPard-Agent — injected above;
            // skip Content-Length — we compute it from body when body is present to avoid duplicates)
            if (headersJson != null && headersJson is JsonObject) {
                headersJson.jsonObject.forEach { (key, value) ->
                    val lk = key.lowercase()
                    if (lk != "host" && lk != "x-penpard-agent" && lk != "content-length") {
                        rawRequest.append("$key: ${value.jsonPrimitive.content}\r\n")
                    }
                }
            }
            
            // Add body if present (Content-Length computed here to avoid duplicate when headers already had it)
            if (body.isNotEmpty()) {
                rawRequest.append("Content-Length: ${body.length}\r\n")
                rawRequest.append("\r\n")
                rawRequest.append(body)
            } else {
                rawRequest.append("\r\n")
            }
            
            // IF use_proxy is TRUE, we route this request specifically through Burp's Proxy Listener
            // Typically localhost:8080. This ensures it appears in "Proxy History".
            // Otherwise, api.http().sendRequest() only appears in "Extensions" or "Logger".
            
            if (useProxy) {
                // Raw socket to Burp Proxy (configurable in PenPard tab) so requests appear in Proxy History.
                try {
                    val proxyHost = server.upstreamProxyHost
                    val proxyPort = server.upstreamProxyPort
                    val proxySocket = Socket(proxyHost, proxyPort)
                    proxySocket.soTimeout = 30000
                    val out: OutputStream = proxySocket.getOutputStream()
                    val inp = proxySocket.getInputStream()
                    if (secure) {
                        // HTTPS: CONNECT tunnel, then TLS, then send rawRequest
                        val connectReq = "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nConnection: close\r\n\r\n"
                        out.write(connectReq.toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        val connectResp = readUntilDoubleNewline(inp)
                        if (!String(connectResp).contains("200")) {
                            proxySocket.close()
                            throw Exception("Proxy CONNECT failed")
                        }
                        val sslSocket = sslContext.socketFactory.createSocket(proxySocket, host, port, true)
                        sslSocket.soTimeout = 30000
                        val sslOut = sslSocket.getOutputStream()
                        val sslIn = sslSocket.getInputStream()
                        sslOut.write(rawRequest.toString().toByteArray(StandardCharsets.UTF_8))
                        sslOut.flush()
                        val responseBytes = sslIn.readBytes()
                        sslSocket.close()
                        val (status, body) = parseHttpResponse(responseBytes)
                        val result = buildJsonObject {
                            put("statusCode", status)
                            put("body_length", body.size)
                            put("body_preview", String(body.take(2000).toByteArray()))
                            put("note", "Routed via Proxy (raw socket)")
                        }
                        return jsonResult(result)
                    } else {
                        // HTTP: Send full absolute URL to proxy (path has encoded query)
                        val fullUrl = if (port == 80) "http://$host$path" else "http://$host:$port$path"
                        val proxyReq = rawRequest.toString().replace("$method $path ", "$method $fullUrl ")
                        out.write(proxyReq.toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        val responseBytes = inp.readBytes()
                        proxySocket.close()
                        val (status, body) = parseHttpResponse(responseBytes)
                        val result = buildJsonObject {
                            put("statusCode", status)
                            put("body_length", body.size)
                            put("body_preview", String(body.take(2000).toByteArray()))
                            put("note", "Routed via Proxy (raw socket)")
                        }
                        return jsonResult(result)
                    }
                } catch (e: Exception) {
                    api.logging().logToError("Failed to route via proxy: ${e.message}, falling back to direct API")
                    // Fallback to normal flow below
                }
            }
            
            // STANDARD API FLOW (Logger/Extension tab only)
            val service = HttpService.httpService(host, port, secure)
            val httpReq = HttpRequest.httpRequest(service, rawRequest.toString())
            
            api.logging().logToOutput("Sending HTTP request to: $url")
            val response = api.http().sendRequest(httpReq)
            
            val result = buildJsonObject {
                put("statusCode", response.response()?.statusCode() ?: 0)
                put("headers", buildJsonArray {
                    response.response()?.headers()?.forEach { h ->
                        add("${h.name()}: ${h.value()}")
                    }
                })
                put("body_length", response.response()?.body()?.length() ?: 0)
                put("body_preview", response.response()?.bodyToString()?.take(2000) ?: "")
            }
            
            // Add to Site Map so it's visible in Burp
            api.siteMap().add(response)
            
            api.logging().logToOutput("Response received: ${response.response()?.statusCode()} - Added to Site Map")
            jsonResult(result)
            
        } catch (e: Exception) {
            api.logging().logToError("sendHttpRequest failed: ${e.message}")
            err("Failed to send request: ${e.message}")
        }
    }
    
    private fun sendRawHttpRequest(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val port = args?.get("port")?.jsonPrimitive?.intOrNull ?: 443
        val secure = args?.get("useHttps")?.jsonPrimitive?.booleanOrNull ?: true
        val useProxy = args?.get("use_proxy")?.jsonPrimitive?.booleanOrNull ?: true
        val rawRequestBody = unescapeRequest(args?.get("request")?.jsonPrimitive?.content ?: return err("Missing request"))
        
        // Inject PenPard Agent header if present
        val penpardSource = args?.get("penpard_source")?.jsonPrimitive?.content
        val requestBody = if (penpardSource != null) {
            val headerEnd = rawRequestBody.indexOf("\r\n\r\n")
            if (headerEnd >= 0) {
                rawRequestBody.substring(0, headerEnd) + "\r\nX-PenPard-Agent: $penpardSource" + rawRequestBody.substring(headerEnd)
            } else {
                rawRequestBody + "\r\nX-PenPard-Agent: $penpardSource\r\n\r\n"
            }
        } else rawRequestBody
        
        return try {
            // Route through Burp Proxy so requests appear in Proxy History
            if (useProxy) {
                try {
                    val proxyHost = server.upstreamProxyHost
                    val proxyPort = server.upstreamProxyPort
                    val proxySocket = Socket(proxyHost, proxyPort)
                    proxySocket.soTimeout = 30000
                    val out: OutputStream = proxySocket.getOutputStream()
                    val inp = proxySocket.getInputStream()
                    if (secure) {
                        // HTTPS: CONNECT tunnel, then TLS, then send raw request
                        val connectReq = "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nConnection: close\r\n\r\n"
                        out.write(connectReq.toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        val connectResp = readUntilDoubleNewline(inp)
                        if (!String(connectResp).contains("200")) {
                            proxySocket.close()
                            throw Exception("Proxy CONNECT failed")
                        }
                        val sslSocket = sslContext.socketFactory.createSocket(proxySocket, host, port, true)
                        sslSocket.soTimeout = 30000
                        val sslOut = sslSocket.getOutputStream()
                        val sslIn = sslSocket.getInputStream()
                        sslOut.write(requestBody.toByteArray(StandardCharsets.UTF_8))
                        sslOut.flush()
                        val responseBytes = sslIn.readBytes()
                        sslSocket.close()
                        val (status, body) = parseHttpResponse(responseBytes)
                        val result = buildJsonObject {
                            put("statusCode", status)
                            put("body_length", body.size)
                            put("body_preview", String(body.take(2000).toByteArray()))
                            put("note", "Routed via Proxy (raw socket)")
                        }
                        return jsonResult(result)
                    } else {
                        // HTTP: Send full absolute URL to proxy
                        val path = requestBody.substringBefore(" HTTP/").substringAfter(" ").trim()
                        val fullUrl = if (port == 80) "http://$host$path" else "http://$host:$port$path"
                        val method = requestBody.substringBefore(" ").trim()
                        val proxyReq = requestBody.replace("$method $path ", "$method $fullUrl ")
                        out.write(proxyReq.toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        val responseBytes = inp.readBytes()
                        proxySocket.close()
                        val (status, body) = parseHttpResponse(responseBytes)
                        val result = buildJsonObject {
                            put("statusCode", status)
                            put("body_length", body.size)
                            put("body_preview", String(body.take(2000).toByteArray()))
                            put("note", "Routed via Proxy (raw socket)")
                        }
                        return jsonResult(result)
                    }
                } catch (e: Exception) {
                    api.logging().logToError("Raw request proxy routing failed: ${e.message}, falling back to direct API")
                    // Fallback to direct API below
                }
            }

            // FALLBACK: Direct API (only appears in Extensions/Logger, not Proxy History)
            val service = HttpService.httpService(host, port, secure)
            val httpReq = HttpRequest.httpRequest(service, requestBody)
            
            api.logging().logToOutput("Sending raw HTTP request to: $host:$port")
            val response = api.http().sendRequest(httpReq)
            
            val result = buildJsonObject {
                put("statusCode", response.response()?.statusCode() ?: 0)
                put("headers", buildJsonArray {
                    response.response()?.headers()?.forEach { h ->
                        add("${h.name()}: ${h.value()}")
                    }
                })
                put("body_length", response.response()?.body()?.length() ?: 0)
                put("body_preview", response.response()?.bodyToString()?.take(2000) ?: "")
            }
            
            // Add to Site Map so it's visible in Burp
            api.siteMap().add(response)
            
            api.logging().logToOutput("Response received: ${response.response()?.statusCode()} - Added to Site Map")
            jsonResult(result)
            
        } catch (e: Exception) {
            api.logging().logToError("sendRawHttpRequest failed: ${e.message}")
            err("Failed to send request: ${e.message}")
        }
    }
    
    private fun spiderUrl(args: JsonObject?): JsonElement {
        val url = args?.get("url")?.jsonPrimitive?.content ?: return err("Missing url")
        api.scope().includeInScope(url)
        return success("Added to scope (Ready for crawling): $url")
    }

    private fun addToScope(args: JsonObject?): JsonElement {
        val url = args?.get("url")?.jsonPrimitive?.content ?: return err("Missing url")
        api.scope().includeInScope(url)
        return success("Added to scope: $url")
    }
    
    private fun getScope(): JsonElement {
        return success("Scope management is active. Use add_to_scope to modify.") 
    }

    private fun getProxyHistory(args: JsonObject?): JsonElement {
        val count = args?.get("count")?.jsonPrimitive?.intOrNull ?: 20
        val regex = args?.get("urlRegex")?.jsonPrimitive?.content
        val excludePenPard = args?.get("excludePenPard")?.jsonPrimitive?.booleanOrNull ?: false
        val includeDetails = args?.get("includeDetails")?.jsonPrimitive?.booleanOrNull ?: false
        
        var history = api.proxy().history()
        if (regex != null) {
            val pat = java.util.regex.Pattern.compile(regex)
            history = history.filter { pat.matcher(it.finalRequest().url()).find() }
        }
        
        if (excludePenPard) {
            history = history.filter { !isPenPardHistoryItem(it) }
        }
        
        val list = history.takeLast(count).reversed()
        
        val result = buildJsonObject {
            put("items", buildJsonArray {
                list.forEach { item ->
                    add(buildJsonObject {
                        put("url", item.finalRequest().url())
                        put("method", item.finalRequest().method())
                        put("status", item.response()?.statusCode() ?: 0)
                        put("time", item.time().toString())
                        put("isPenPard", isPenPardHistoryItem(item))
                        
                        if (includeDetails) {
                            // Request details
                            try {
                                val reqHeaders = item.finalRequest().headers().joinToString("\n") { "${it.name()}: ${it.value()}" }
                                put("requestHeaders", reqHeaders.take(1000))
                            } catch (e: Exception) {}
                            
                            try {
                                val bodyStr = item.finalRequest().bodyToString()
                                if (bodyStr.isNotEmpty()) put("requestBody", bodyStr.take(500))
                            } catch (e: Exception) {}
                            
                            // Response details
                            try {
                                val respBody = item.response()?.bodyToString()
                                if (respBody != null) put("responseBody", respBody.take(500))
                            } catch (e: Exception) {}
                            
                            // Annotations
                            try {
                                val notes = item.annotations().notes()
                                if (!notes.isNullOrEmpty()) put("notes", notes)
                                val highlight = item.annotations().highlightColor()
                                if (highlight != null) put("highlight", highlight.name)
                            } catch (e: Exception) {}
                        }
                    })
                }
            })
            put("count", list.size)
            put("totalHistory", api.proxy().history().size)
        }
        return jsonResult(result)
    }

    /**
     * Returns the Cookie header from the most recent user (non-PenPard) request to the given host.
     * Use when the user has logged in via browser through Burp (e.g. Google OAuth) so the agent
     * can send authenticated requests with the same session.
     */
    private fun getSessionCookies(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val hostLower = host.lowercase().removePrefix("www.")
        var history = api.proxy().history()
        history = history.filter { !isPenPardHistoryItem(it) }
        history = history.filter { item ->
            val url = item.finalRequest().url().lowercase()
            url.contains(hostLower) || url.contains("www.$hostLower")
        }
        val latest = history.lastOrNull() ?: return jsonResult(buildJsonObject {
            put("cookieHeader", "")
            put("note", "No user requests found for host: $host. Log in via browser through Burp first, then retry.")
        })
        val cookieHeader = latest.finalRequest().headers()
            .firstOrNull { it.name().equals("Cookie", true) }
            ?.value() ?: ""
        return jsonResult(buildJsonObject {
            put("cookieHeader", cookieHeader)
            put("fromUrl", latest.finalRequest().url())
            if (cookieHeader.isEmpty()) put("note", "Latest request to host had no Cookie header.")
        })
    }

    /**
     * Returns Cookie and Authorization headers from proxy history for the given host,
     * newest to oldest (last N user requests). Used at planning phase to discover session/auth.
     */
    private fun getCookiesAndAuthForHost(args: JsonObject?): JsonElement {
        val host = args?.get("host")?.jsonPrimitive?.content ?: return err("Missing host")
        val maxItems = args?.get("maxItems")?.jsonPrimitive?.intOrNull ?: 50
        val hostLower = host.lowercase().removePrefix("www.")
        var history = api.proxy().history()
        history = history.filter { !isPenPardHistoryItem(it) }
        history = history.filter { item ->
            val url = item.finalRequest().url().lowercase()
            url.contains(hostLower) || url.contains("www.$hostLower")
        }
        val newestFirst = history.takeLast(maxItems).reversed()
        val entries = buildJsonArray {
            newestFirst.forEach { item ->
                val req = item.finalRequest()
                val cookie = req.headers().firstOrNull { it.name().equals("Cookie", true) }?.value() ?: ""
                val auth = req.headers().firstOrNull { it.name().equals("Authorization", true) }?.value() ?: ""
                if (cookie.isNotEmpty() || auth.isNotEmpty()) {
                    add(buildJsonObject {
                        put("cookie", cookie)
                        put("authorization", auth)
                        put("fromUrl", req.url())
                    })
                }
            }
        }
        return jsonResult(buildJsonObject {
            put("entries", entries)
            put("count", entries.size)
            put("host", host)
        })
    }

    private fun getSitemap(args: JsonObject?): JsonElement {
        val prefix = args?.get("prefix")?.jsonPrimitive?.content ?: ""
        val urls = api.siteMap().requestResponses()
            .map { it.request().url() }
            .filter { it.startsWith(prefix) }
            .distinct()
            .take(100)
            
        val result = buildJsonObject {
            put("urls", buildJsonArray { urls.forEach { add(it) } })
        }
        return jsonResult(result)
    }

    private fun getScannerIssues(args: JsonObject?): JsonElement {
        val count = args?.get("count")?.jsonPrimitive?.intOrNull ?: 20
        // val severity = args?.str("minSeverity") ?: "Low" 
        
        val issues = api.siteMap().issues().take(count)
            
        val result = buildJsonObject {
            put("issues", buildJsonArray {
                issues.forEach { i ->
                    // Get request/response from sitemap by matching URL
                    var requestStr = ""
                    var responseStr = ""
                    
                    try {
                        val issueUrl = i.httpService()?.toString() ?: ""
                        val requestResponse = api.siteMap().requestResponses()
                            .firstOrNull { 
                                val reqUrl = it.request().url().toString()
                                reqUrl.startsWith(issueUrl) || issueUrl.startsWith(reqUrl)
                            }
                        
                        if (requestResponse != null) {
                            requestStr = requestResponse.request().toString()
                            responseStr = requestResponse.response()?.toString() ?: ""
                        }
                    } catch (e: Exception) {
                        // If requestResponse not available, leave empty
                        api.logging().logToOutput("Could not get request/response for issue: ${e.message}")
                    }
                    
                    add(buildJsonObject {
                        put("name", i.name())
                        put("url", i.httpService()?.toString() ?: "")
                        put("severity", i.severity().name)
                        put("confidence", i.confidence().name)
                        put("detail", (i.detail() ?: "").take(500)) // Truncate detail
                        put("remediation", (i.remediation() ?: "").take(500)) // Remediation advice
                        put("request", requestStr) // Full HTTP request
                        put("response", responseStr) // Full HTTP response
                    })
                }
            })
        }
        return jsonResult(result)
    }

    // --- ACTIVITY MONITORING ---
    
    /**
     * True if this proxy history entry is a PenPard agent request. The proxy handler strips
     * X-PenPard-Agent before saving, so we identify by annotation notes ("[PenPard] Agent Request").
     * Use this for filtering; do not rely on request header in history.
     */
    private fun isPenPardHistoryItem(item: burp.api.montoya.proxy.ProxyHttpRequestResponse): Boolean {
        return item.annotations().notes()?.contains("PenPard") == true
    }
    
    /**
     * Analyze only USER traffic for Smart Assist. PenPard agent requests (annotated in history) are
     * always excluded — no point assisting on our own requests, and it reduces noise/load.
     */
    private fun getUserActivity(args: JsonObject?): JsonElement {
        val count = args?.get("count")?.jsonPrimitive?.intOrNull ?: 50
        
        val allHistory = api.proxy().history()
        val userHistory = allHistory.filter { !isPenPardHistoryItem(it) }
        val recent = userHistory.takeLast(count)
        
        if (recent.isEmpty()) {
            return jsonResult(buildJsonObject {
                put("totalUserRequests", 0)
                put("dominantActivity", "idle")
                put("patterns", buildJsonObject {})
                put("uniqueEndpoints", 0)
                put("endpoints", buildJsonArray {})
                put("payloadExamples", buildJsonArray {})
                put("items", buildJsonArray {})
            })
        }
        
        // Pattern detection
        val patterns = mutableMapOf<String, Int>()
        val endpoints = mutableSetOf<String>()
        val payloadExamples = mutableListOf<String>()
        val targetHosts = mutableSetOf<String>()
        
        recent.forEach { item ->
            val url = item.finalRequest().url()
            val method = item.finalRequest().method()
            val body = try { item.finalRequest().bodyToString() } catch (e: Exception) { "" }
            val fullContent = "$url $body".lowercase()
            
            // Extract host
            try {
                val host = java.net.URL(if (url.startsWith("http")) url else "https://$url").host
                targetHosts.add(host)
            } catch (e: Exception) {}
            
            endpoints.add("$method $url")
            
            // SQLi patterns
            val sqliPatterns = listOf("' or", "union select", "1=1", "sleep(", "waitfor", 
                "order by", "group by", "having", "benchmark(", "extractvalue", "updatexml",
                "' and '", "\" or \"", "' or '", "--", "/**/", "information_schema")
            if (sqliPatterns.any { fullContent.contains(it) }) {
                patterns["sqli"] = (patterns["sqli"] ?: 0) + 1
                if (payloadExamples.size < 10) payloadExamples.add("SQLi: $method $url")
            }
            
            // XSS patterns
            val xssPatterns = listOf("<script", "alert(", "onerror=", "<img", "javascript:", 
                "onload=", "<svg", "onfocus=", "onmouseover=", "document.cookie", "prompt(",
                "confirm(", "<iframe", "eval(")
            if (xssPatterns.any { fullContent.contains(it) }) {
                patterns["xss"] = (patterns["xss"] ?: 0) + 1
                if (payloadExamples.size < 10) payloadExamples.add("XSS: $method $url")
            }
            
            // LFI / Path Traversal patterns
            val lfiPatterns = listOf("../", "/etc/passwd", "/etc/shadow", "..%2f", 
                "....//", "..\\", "/proc/self", "file:///", "php://filter")
            if (lfiPatterns.any { fullContent.contains(it) }) {
                patterns["lfi"] = (patterns["lfi"] ?: 0) + 1
                if (payloadExamples.size < 10) payloadExamples.add("LFI: $method $url")
            }
            
            // Command Injection patterns
            val cmdiPatterns = listOf("; ls", "| cat", "`id`", "\$(", "; whoami", 
                "| ping", "; sleep", "&& cat", "|| cat")
            if (cmdiPatterns.any { fullContent.contains(it) }) {
                patterns["cmdi"] = (patterns["cmdi"] ?: 0) + 1
                if (payloadExamples.size < 10) payloadExamples.add("CMDi: $method $url")
            }
            
            // SSRF patterns
            val ssrfPatterns = listOf("127.0.0.1", "localhost", "169.254.169.254", 
                "0.0.0.0", "[::", "metadata.google", "http://[")
            if (ssrfPatterns.any { fullContent.contains(it) } && method == "POST") {
                patterns["ssrf"] = (patterns["ssrf"] ?: 0) + 1
                if (payloadExamples.size < 10) payloadExamples.add("SSRF: $method $url")
            }
        }
        
        // Determine dominant activity
        val dominantActivity = if (patterns.isEmpty()) "browsing" 
            else patterns.maxByOrNull { it.value }?.key ?: "browsing"
        
        val result = buildJsonObject {
            put("totalUserRequests", recent.size)
            put("totalPenPardRequests", allHistory.size - userHistory.size)
            put("dominantActivity", dominantActivity)
            put("patterns", buildJsonObject {
                patterns.forEach { (k, v) -> put(k, v) }
            })
            put("uniqueEndpoints", endpoints.size)
            put("targetHosts", buildJsonArray { targetHosts.forEach { add(it) } })
            put("endpoints", buildJsonArray { endpoints.take(20).forEach { add(it) } })
            put("payloadExamples", buildJsonArray { payloadExamples.forEach { add(it) } })
            // Last 15 items for context
            put("items", buildJsonArray {
                recent.takeLast(15).reversed().forEach { item ->
                    add(buildJsonObject {
                        put("url", item.finalRequest().url())
                        put("method", item.finalRequest().method())
                        put("status", item.response()?.statusCode() ?: 0)
                        put("time", item.time().toString())
                        try {
                            val bodyPreview = item.finalRequest().bodyToString().take(200)
                            if (bodyPreview.isNotEmpty()) put("bodyPreview", bodyPreview)
                        } catch (e: Exception) {}
                    })
                }
            })
        }
        
        return jsonResult(result)
    }

    // --- Utils ---
    private fun urlEncode(args: JsonObject?) = success(URLEncoder.encode(args?.get("data")?.jsonPrimitive?.content ?: "", StandardCharsets.UTF_8))
    private fun urlDecode(args: JsonObject?) = success(URLDecoder.decode(args?.get("data")?.jsonPrimitive?.content ?: "", StandardCharsets.UTF_8))
    private fun base64Encode(args: JsonObject?) = success(Base64.getEncoder().encodeToString((args?.get("data")?.jsonPrimitive?.content?:"").toByteArray()))
    private fun base64Decode(args: JsonObject?) = success(String(Base64.getDecoder().decode(args?.get("data")?.jsonPrimitive?.content?:"")))
    
    private fun hashData(args: JsonObject?): JsonElement {
        val data = args?.get("data")?.jsonPrimitive?.content ?: return err("Missing data")
        val algo = args?.get("algorithm")?.jsonPrimitive?.content ?: "SHA-256"
        return try {
            val bytes = MessageDigest.getInstance(algo).digest(data.toByteArray())
            val hex = bytes.joinToString("") { "%02x".format(it) }
            success(hex)
        } catch (e: Exception) { err("Invalid algorithm: $algo") }
    }

    // --- Pentest Helpers ---
    private fun extractLinks(args: JsonObject?): JsonElement {
        val html = args?.get("html")?.jsonPrimitive?.content ?: return err("Missing html")
        val pattern = java.util.regex.Pattern.compile("(href|src)=[\"']([^\"']*)[\"']")
        val matcher = pattern.matcher(html)
        val links = mutableListOf<String>()
        while (matcher.find()) {
            links.add(matcher.group(2))
        }
        return jsonResult(buildJsonObject { put("links", buildJsonArray { links.distinct().forEach { add(it) } }) })
    }

    private fun extractComments(args: JsonObject?): JsonElement {
        val html = args?.get("html")?.jsonPrimitive?.content ?: return err("Missing html")
        val pattern = java.util.regex.Pattern.compile("<!--(.*?)-->", java.util.regex.Pattern.DOTALL)
        val matcher = pattern.matcher(html)
        val comments = mutableListOf<String>()
        while (matcher.find()) {
            comments.add(matcher.group(1).trim())
        }
        return jsonResult(buildJsonObject { put("comments", buildJsonArray { comments.forEach { add(it) } }) })
    }

    private fun generatePayloads(args: JsonObject?): JsonElement {
        val type = args?.get("type")?.jsonPrimitive?.content?.lowercase() ?: "all"
        val payloads = mutableListOf<String>()
        
        if (type == "sqli" || type == "all") {
            payloads.add("' OR 1=1 --")
            payloads.add("' UNION SELECT NULL, version() --")
            payloads.add("admin' --")
        }
        if (type == "xss" || type == "all") {
            payloads.add("<script>alert(1)</script>")
            payloads.add("<img src=x onerror=alert(1)>")
            payloads.add("javascript:alert(1)")
        }
        return jsonResult(buildJsonObject { put("payloads", buildJsonArray { payloads.forEach { add(it) } }) })
    }

    // --- Config ---
    private fun getBurpVersion() = success(api.burpSuite().version().toString())
    
    private fun setIntercept(enabled: Boolean): JsonElement {
        if (enabled) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        return success("Intercept ${if(enabled) "Enabled" else "Disabled"}")
    }
}
