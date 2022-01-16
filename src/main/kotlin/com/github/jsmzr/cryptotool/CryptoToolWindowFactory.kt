package com.github.jsmzr.cryptotool

import com.github.jsmzr.cryptotool.ui.CryptoToolMainWindow
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.daead.DeterministicAeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.mac.MacConfig
import com.google.crypto.tink.signature.SignatureConfig
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory

class CryptoToolWindowFactory: ToolWindowFactory {
    init {
        AeadConfig.register()
        DeterministicAeadConfig.register()
        MacConfig.register()
        SignatureConfig.register()
        HybridConfig.register()
    }
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val window = CryptoToolMainWindow(project)
        val factory = ContentFactory.SERVICE.getInstance()
        val content = factory.createContent(window.root, "", false)
        toolWindow.contentManager.addContent(content)
    }
}