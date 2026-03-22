package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File

class ZygiskDetector {

    fun detect(): DetectionItem {
        val evidence = linkedSetOf<String>()
        val trustedLocked = DetectorTrust.bootLooksTrustedLocked()

        try {
            File("/proc/self/maps").forEachLine { line ->
                if (DetectorTrust.isLikelyRuntimeInjectionEvidence(line, trustedLocked)) {
                    evidence += line.trim().take(140)
                }
            }
        } catch (_: Exception) {}

        try {
            File("/proc/net/unix").forEachLine { line ->
                if (DetectorTrust.isLikelyRuntimeInjectionEvidence(line, trustedLocked)) {
                    val trimmed = line.trim()
                    val path = trimmed.substringAfterLast(" ").take(140)
                    if (path.isNotBlank()) evidence += path
                }
            }
        } catch (_: Exception) {}

        try {
            val sensitiveEnvKeys = HardcodedSignals.envKeys + "JAVA_TOOL_OPTIONS"
            System.getenv().forEach { (key, value) ->
                val entry = "$key=$value"
                if (sensitiveEnvKeys.any { key.equals(it, ignoreCase = true) } &&
                    DetectorTrust.isLikelyRuntimeInjectionEvidence(entry, trustedLocked)) {
                    evidence += entry.take(140)
                }
            }
        } catch (_: Exception) {}

        return DetectionItem(
            id = "zygisk_runtime",
            name = "Runtime Injection Framework",
            description = "Zygisk, LSPosed, Riru, LSPatch, TrickyStore or similar runtime artifacts",
            category = DetectionCategory.MAGISK,
            severity = Severity.HIGH,
            detected = evidence.isNotEmpty(),
            detail = evidence.take(6).joinToString("\n").ifEmpty { null }
        )
    }
}
