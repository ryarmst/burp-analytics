plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2024.12")
    implementation("com.google.code.gson:gson:2.11.0")
}

tasks.jar {
    archiveBaseName.set("analytics-burp-extension")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(sourceSets.main.get().output)
    // Bundle runtime deps (e.g. Gson). Montoya stays compileOnly and is not included.
    from(
        configurations.runtimeClasspath.get().map { f ->
            if (f.isDirectory) f else zipTree(f)
        }
    ) {
        exclude("META-INF/MANIFEST.MF")
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}
