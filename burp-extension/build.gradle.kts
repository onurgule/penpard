plugins {
    kotlin("jvm") version "2.3.0"
    kotlin("plugin.serialization") version "2.3.0"
    id("io.github.goooler.shadow") version "8.1.8"
}

group = "net.penpard"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API (2025.2 for latest ProxyRequestHandler and Annotations support)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.2")
    
    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    
    // JSON Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    
    // NanoHTTPD
    implementation("org.nanohttpd:nanohttpd:2.3.1")
}

// Use Java 17 for compatibility with Burp Suite
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.shadowJar {
    archiveBaseName.set("penpard-mcp-connect")
    archiveClassifier.set("")
    archiveVersion.set(version.toString())
    
    manifest {
        attributes(
            "Extension-Name" to "PenPard MCP Connect",
            "Extension-Version" to version
        )
    }
    
    // Exclude Montoya API from fat JAR (provided by Burp)
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
