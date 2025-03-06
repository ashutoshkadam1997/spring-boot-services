package dev.ashutosh.sc.learnSpringSecurity.jwtutils;

import java.io.IOException;
import java.io.Serializable;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * This class extends Spring’s AuthenticationEntryPoint class and
 * rejects every unauthenticated request with an error code 401 sent back to the client.
 * We have overridden the commence() method of AuthenticationEntryPoint class to do that.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = 1L;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
