plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.flechazo"
version = "1.1"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API is vendored under libs/ so an offline/internal-network
    // clone can build without fetching the dependency. It is compileOnly:
    // at runtime Burp Suite itself provides these classes, so the dist jar must
    // NOT bundle them (would conflict with Burp's own copy).
    implementation(files("libs/burp-extensions-montoya-api-2026.7.jar"))
    testImplementation(files("libs/burp-extensions-montoya-api-2026.7.jar"))
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.google.code.gson:gson:2.11.0")
    // Syntax-highlighting/line-numbered editor for the "关联源码" tab —
    // previously a bare monospaced JTextArea with no highlighting or gutter.
    implementation("com.fifesoft:rsyntaxtextarea:3.6.0")
    // F-1: Playwright for browser automation (DOM XSS detection, SPA discovery)
    implementation("com.microsoft.playwright:playwright:1.49.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.mockito:mockito-core:5.11.0")
    testImplementation("org.assertj:assertj-core:3.25.3")
}

tasks.shadowJar {
    archiveBaseName.set("API-Sentinel")
    archiveClassifier.set("")
    relocate("org.yaml.snakeyaml", "com.flechazo.apisentinel.shaded.snakeyaml")
    relocate("com.google.gson", "com.flechazo.apisentinel.shaded.gson")
    relocate("org.fife", "com.flechazo.apisentinel.shaded.fife")
    // F-1: Playwright relocation
    relocate("com.microsoft.playwright", "com.flechazo.apisentinel.shaded.playwright")
    // F-1: Playwright bundles a Node.js driver (~124MB per platform).
    // Keep only the current build platform's driver to minimize jar size.
    // The driver is auto-extracted to ~/.api-sentinel/playwright-driver/ on first use.
    val currentOs = when {
        org.gradle.internal.os.OperatingSystem.current().isMacOsX -> "mac"
        org.gradle.internal.os.OperatingSystem.current().isWindows -> "win32"
        else -> "linux"
    }
    val arch = System.getProperty("os.arch")
    val driverDir = if (arch == "aarch64" || arch == "arm64") "${currentOs}-arm64" else currentOs
    val driverPattern = when (currentOs) {
        "mac" -> if (driverDir == "mac-arm64") "mac-arm64" else "mac"
        "win32" -> "win32_x64"
        else -> if (driverDir == "linux-arm64") "linux-arm64" else "linux"
    }
    // Exclude driver platforms that don't match the current build OS
    for (platform in listOf("linux", "linux-arm64", "mac", "mac-arm64", "win32_x64")) {
        if (platform != driverPattern) {
            exclude("driver/$platform/**")
        }
    }
    destinationDirectory.set(file("dist"))
}

// Fat jar: includes all runtime dependencies so the jar is self-contained
// for CLI mode (java -jar). For Burp extension mode, Burp provides the
// Montoya API at runtime so the duplication is harmless.
tasks.jar {
    manifest {
        attributes("Implementation-Title" to "API Sentinel")
        attributes("Implementation-Version" to version)
        attributes("Main-Class" to "com.flechazo.apisentinel.standalone.StandaloneMain")
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.test {
    useJUnitPlatform()
}

// F-1: Install Playwright Chromium browser for local development.
// Usage: ./gradlew installChromium
tasks.register<JavaExec>("installChromium") {
    group = "playwright"
    description = "Install Playwright Chromium browser to ~/.cache/ms-playwright"
    classpath = configurations.runtimeClasspath.get()
    mainClass.set("com.microsoft.playwright.CLI")
    args("install", "chromium")
}
