plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "app.tgproxy.simple"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    defaultConfig { applicationId = "app.tgproxy.simple"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "1.0" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    signingConfigs {
        create("distribution") {
            System.getenv("TG_KEYSTORE")?.let { storeFile = file(it) }
            storePassword = System.getenv("TG_STORE_PASSWORD")
            keyAlias = "tgproxy"
            keyPassword = System.getenv("TG_STORE_PASSWORD")
        }
    }
    buildTypes { getByName("release") { signingConfig = signingConfigs.getByName("distribution"); isMinifyEnabled = false } }
    testOptions { unitTests.isReturnDefaultValues = true }
}
dependencies { testImplementation("junit:junit:4.13.2") }
