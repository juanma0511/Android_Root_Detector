# Kknd Root Detector

![Banner](art/banner.png)

Kknd Root Detector is an Android application that performs deep, multi-layer detection of root access, hook frameworks, SELinux policy tampering, and system integrity violations — using both Kotlin and native C++ checks.

---

## Features — v3.1

### Native (C++) — 71 checks

| Category | Description |
|---|---|
| Binary scan | `su`, root manager packages, suspicious paths |
| Mount namespace | Bind-mounts, overlayfs, namespace isolation |
| Property tampering | Resetprop scan across all partition prop files; `__system_property_serial` drift; PIF/TrickyStore spoof configs |
| SELinux | `attr/current` write probe (root contexts in policy); DirtySepolicy `selinux_check_access` rule checks |
| Zygisk / LSPosed | Module presence, memory maps, JNI hook traces |
| Hardware security | Keystore attestation, TEE status, boot state |

### Kotlin — 68 checks

Mirrors the native layer with JVM-level checks: package manager scans, reflection-based `SELinux.checkSELinuxAccess`, prop reads, Play Integrity API integration, and certificate chain validation.

---

## Installation

Download the latest signed APK from the **Releases page**:

https://github.com/juanma0511/Kknd_Root_Detector/releases

Two APK variants are provided per release — pick the one matching your device:

| File | ABI |
|---|---|
| `RootDetector-3.1-arm64-v8a-release.apk` | 64-bit (most modern devices) |
| `RootDetector-3.1-armeabi-v7a-release.apk` | 32-bit |

Or grab the latest CI artifact from **Actions**.

---

## Build From Source

### Requirements

- Android Studio Hedgehog or later
- Android SDK (API 36)
- NDK 27
- JDK 17
- CMake 3.22.1

### Steps

```bash
git clone https://github.com/juanma0511/Kknd_Root_Detector.git
cd Kknd_Root_Detector
./gradlew assembleDebug
```

The debug APK will be at:

    app/build/outputs/apk/debug/*.apk

For a signed release build see the **Release workflow** section below.

---

## Release Workflow

Releases are built and signed automatically via GitHub Actions when a `v*` tag is pushed:

```bash
git tag v3.1
git push origin v3.1
```

Or trigger manually from the **Actions** tab using the **Release Build** workflow.

### Required GitHub Secrets

| Secret | Value |
|---|---|
| `KEYSTORE_BASE64` | Base64-encoded `.jks` keystore file |
| `STORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Key alias inside the keystore |
| `KEY_PASSWORD` | Key password |

Generate a keystore if you don't have one:

```bash
keytool -genkey -v -keystore keystore.jks -alias mykey \
  -keyalg RSA -keysize 2048 -validity 10000
base64 -w0 keystore.jks
```

---

## Project Preview

<img src="art/rootdetection.jpg" width="350">

---

## Use Cases

- Testing rooted Android devices
- Studying root and hook framework detection techniques
- Learning Android native security (SELinux, properties, mount namespaces)
- Developing root detection in production apps

---

## Credits

Native detection ideas inspired by:

- https://github.com/reveny/Android-Native-Root-Detector
- Duck-Detector-Refactoring (SELinux detection approach)

---

## Reporting Issues

- Open an issue: https://github.com/juanma0511/Kknd_Root_Detector/issues
- Telegram: https://t.me/juanma0511

---

## Disclaimer

This project is provided for **educational and research purposes only**.
Do not use it to bypass security protections in applications without authorization.
