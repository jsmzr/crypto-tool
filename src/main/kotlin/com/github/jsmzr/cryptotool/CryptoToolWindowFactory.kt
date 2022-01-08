package com.github.jsmzr.cryptotool

import com.github.jsmzr.cryptotool.ui.CryptoToolMainWindow
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory

class CryptoToolWindowFactory: ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val window = CryptoToolMainWindow(project)
        val factory = ContentFactory.SERVICE.getInstance()
        val content = factory.createContent(window.root, "", false)
        toolWindow.contentManager.addContent(content)
    }
}