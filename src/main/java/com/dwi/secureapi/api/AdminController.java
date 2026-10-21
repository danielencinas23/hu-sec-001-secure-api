package com.dwi.secureapi.api;

import java.lang.management.ManagementFactory;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints de administración. La regla {@code /api/admin/** -> hasRole("ADMIN")} de
 * SecurityConfig hace que un usuario autenticado sin ese rol reciba 403 Forbidden.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Runtime runtime = Runtime.getRuntime();
        return Map.of(
                "uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime(),
                "availableProcessors", runtime.availableProcessors(),
                "usedMemoryMb", (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024));
    }
}
