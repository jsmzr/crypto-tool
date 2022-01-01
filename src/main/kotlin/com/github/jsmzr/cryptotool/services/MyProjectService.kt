package com.github.jsmzr.cryptotool.services

import com.intellij.openapi.project.Project
import com.github.jsmzr.cryptotool.MyBundle

class MyProjectService(project: Project) {

    init {
        println(MyBundle.message("projectService", project.name))
    }
}
