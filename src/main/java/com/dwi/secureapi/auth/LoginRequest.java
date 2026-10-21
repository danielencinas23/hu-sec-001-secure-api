package com.dwi.secureapi.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "el usuario es obligatorio") @Size(max = 100) String username,
        @NotBlank(message = "la contraseña es obligatoria") @Size(max = 200) String password) {

    /** Evita que la contraseña aparezca en logs si alguien imprime el objeto. */
    @Override
    public String toString() {
        return "LoginRequest[username=" + username + ", password=****]";
    }
}
