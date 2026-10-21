package com.dwi.secureapi.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logger dedicado a eventos de seguridad. En logback-spring.xml se envía, además de a consola,
 * al fichero {@code logs/security-audit.log}.
 */
public final class SecurityAudit {

    public static final String LOGGER_NAME = "SECURITY_AUDIT";

    public static final Logger LOG = LoggerFactory.getLogger(LOGGER_NAME);

    private SecurityAudit() {
    }
}
