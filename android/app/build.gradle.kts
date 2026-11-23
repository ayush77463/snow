import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.snow"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.snow"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "4.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            val keystoreProperties = Properties()
            if (keystorePropertiesFile.exists()) {
                keystorePropertiesFile.inputStream().use { keystoreProperties.load(it) }
            }

            val keystorePath = System.getenv("SNOW_KEYSTORE_PATH")
                ?: (project.findProperty("SNOW_KEYSTORE_PATH") as String?)
                ?: keystoreProperties.getProperty("storeFile")
            val keystorePassword = System.getenv("SNOW_KEYSTORE_PASSWORD")
                ?: (project.findProperty("SNOW_KEYSTORE_PASSWORD") as String?)
                ?: keystoreProperties.getProperty("storePassword")
            val keyAlias = System.getenv("SNOW_KEY_ALIAS")
                ?: (project.findProperty("SNOW_KEY_ALIAS") as String?)
                ?: keystoreProperties.getProperty("keyAlias")
            val keyPassword = System.getenv("SNOW_KEY_PASSWORD")
                ?: (project.findProperty("SNOW_KEY_PASSWORD") as String?)
                ?: keystoreProperties.getProperty("keyPassword")

            if (!keystorePath.isNullOrBlank() && file(keystorePath).exists()) {
                storeFile = file(keystorePath)
                storePassword = keystorePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val releaseSigning = signingConfigs.getByName("release")
            if (releaseSigning.storeFile != null) {
                signingConfig = releaseSigning
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.fragment:fragment-ktx:1.7.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.6")
    implementation("androidx.documentfile:documentfile:1.0.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-service:2.8.6")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // OkHttp WebSocket Client
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // QR Code Scanning (ZXing Embedded)
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // RFC 6455 WebSocket Server with TLS 1.2+ for Android Peer Host Mode
    implementation("org.java-websocket:Java-WebSocket:1.5.7")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.json:json:20231013")
}
