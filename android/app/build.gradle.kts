
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// One version for every platform: ../../VERSION
val ckVersion = rootProject.file("../VERSION").readText().trim()
val ckParts = ckVersion.substringBefore("-").split(".").map { it.toIntOrNull() ?: 0 } + listOf(0, 0, 0)

// Shared screens from ../../ui are packaged as app assets (assets/ui/...)
val uiAssets = layout.buildDirectory.dir("generated/uiAssets")
val copyUi by tasks.registering(Sync::class) {
    from(rootProject.file("../ui")) { include("*.html", "mobile/**") }
    into(uiAssets.map { it.dir("ui") })
}

android {
    namespace = "com.corekit.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.corekit.app"
        minSdk = 26
        targetSdk = 35
        versionName = ckVersion
        versionCode = ckParts[0] * 10000 + ckParts[1] * 100 + ckParts[2]
        // libcorekit.so (shared Go code) and libxray.so (proxy engine) are 64-bit ARM builds
        ndk { abiFilters += "arm64-v8a" }
    }

    signingConfigs {
        val ks = rootProject.file("release.jks")
        if (ks.exists()) {
            create("release") {
                storeFile = ks
                storePassword = System.getenv("CK_KEYSTORE_PASS")
                keyAlias = "corekit"
                keyPassword = System.getenv("CK_KEYSTORE_PASS")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets["main"].assets.srcDir(uiAssets)
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        // the bundled programs must be extracted to run
        jniLibs.useLegacyPackaging = true
        // ship the programs byte-for-byte (the emulator's saved states are tied to its exact build)
        jniLibs.keepDebugSymbols += "**/*.so"
    }
}

tasks.named("preBuild") { dependsOn(copyUi) }

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.webkit:webkit:1.12.1")
}
