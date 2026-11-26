import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val releaseKeystorePropertiesFile = rootProject.file("keystore.properties")
val releaseKeystoreProperties = Properties()
if (releaseKeystorePropertiesFile.exists()) {
    releaseKeystorePropertiesFile.inputStream().use { releaseKeystoreProperties.load(it) }
}

val releaseKeystorePath = (System.getenv("SNOW_KEYSTORE_PATH")
    ?: (project.findProperty("SNOW_KEYSTORE_PATH") as String?)
    ?: releaseKeystoreProperties.getProperty("storeFile"))?.trim()
val releaseKeystorePassword = System.getenv("SNOW_KEYSTORE_PASSWORD")
    ?: (project.findProperty("SNOW_KEYSTORE_PASSWORD") as String?)
    ?: releaseKeystoreProperties.getProperty("storePassword")
val releaseKeyAlias = System.getenv("SNOW_KEYSTORE_ALIAS")
    ?: System.getenv("SNOW_KEY_ALIAS")
    ?: (project.findProperty("SNOW_KEYSTORE_ALIAS") as String?)
    ?: (project.findProperty("SNOW_KEY_ALIAS") as String?)
    ?: releaseKeystoreProperties.getProperty("keyAlias")
val releaseKeyPassword = System.getenv("SNOW_KEY_PASSWORD")
    ?: (project.findProperty("SNOW_KEY_PASSWORD") as String?)
    ?: releaseKeystoreProperties.getProperty("keyPassword")

val releaseStoreFile = releaseKeystorePath?.takeIf { it.isNotBlank() }?.let { file(it) }
val releaseSigningValidationError: String? = when {
    releaseStoreFile == null || !releaseStoreFile.isFile ->
        "Fail-closed release signing check failed: release keystore file is missing or not found. Configure SNOW_KEYSTORE_PATH or android/keystore.properties."
    releaseKeystorePassword.isNullOrBlank() ->
        "Fail-closed release signing check failed: SNOW_KEYSTORE_PASSWORD (or storePassword) is missing."
    releaseKeyAlias.isNullOrBlank() ->
        "Fail-closed release signing check failed: SNOW_KEYSTORE_ALIAS (or keyAlias) is missing."
    releaseKeyPassword.isNullOrBlank() ->
        "Fail-closed release signing check failed: SNOW_KEY_PASSWORD (or keyPassword) is missing."
    else -> null
}

val releaseSigningTasks = setOf(
    "validateSigningRelease",
    "packageRelease",
    "assembleRelease",
    "signReleaseBundle",
    "packageReleaseBundle",
    "bundleRelease"
)
tasks.configureEach {
    if (name in releaseSigningTasks) {
        doFirst {
            if (releaseSigningValidationError != null) {
                throw org.gradle.api.GradleException(releaseSigningValidationError)
            }
        }
    }
}

android {
    namespace = "org.snow"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.snow"
        minSdk = 26
        targetSdk = 34
        versionCode = 4
        versionName = "5.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (releaseSigningValidationError == null && releaseStoreFile != null) {
                storeFile = releaseStoreFile
                storePassword = releaseKeystorePassword
                this.keyAlias = releaseKeyAlias
                this.keyPassword = releaseKeyPassword
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
            signingConfig = if (releaseSigningValidationError == null) {
                signingConfigs.getByName("release")
            } else {
                null
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
        buildConfig = true
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
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

    // Compose BOM & UI
    val composeBom = platform("androidx.compose:compose-bom:2024.02.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.json:json:20231013")
}
