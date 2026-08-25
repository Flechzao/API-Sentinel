plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.flechazo"
version = "1.0"

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
    compileOnly(files("libs/burp-extensions-montoya-api-2026.7.jar"))
    testImplementation(files("libs/burp-extensions-montoya-api-2026.7.jar"))
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.google.code.gson:gson:2.11.0")
    // Syntax-highlighting/line-numbered editor for the "关联源码" tab —
    // previously a bare monospaced JTextArea with no highlighting or gutter.
    implementation("com.fifesoft:rsyntaxtextarea:3.6.0")
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
    destinationDirectory.set(file("dist"))
}

tasks.jar {
    manifest {
        attributes("Implementation-Title" to "API Sentinel")
        attributes("Implementation-Version" to version)
    }
}

tasks.test {
    useJUnitPlatform()
}
