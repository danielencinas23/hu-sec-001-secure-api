package com.dwi.secureapi.security;

import com.dwi.secureapi.logging.SecurityAudit;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/** Registra en el log de auditoría los intentos de login (usuario/contraseña) exitosos y fallidos. */
@Component
public class SecurityEventListener {

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication() instanceof UsernamePasswordAuthenticationToken) {
            SecurityAudit.LOG.info("LOGIN_SUCCESS usuario={} autoridades={}", event.getAuthentication().getName(),
                    event.getAuthentication().getAuthorities());
        }
    }

    /** Los fallos de token Bearer ya los registra JsonAuthenticationEntryPoint (401 TOKEN_INVALID). */
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        if (!(event.getAuthentication() instanceof UsernamePasswordAuthenticationToken)) {
            return;
        }
        SecurityAudit.LOG.warn("LOGIN_FAILURE usuario={} motivo={}", event.getAuthentication().getName(),
                event.getException().getClass().getSimpleName());
    }
}
