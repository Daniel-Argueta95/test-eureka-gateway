package com.test.eureka_client.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        System.out.println(">>> Filtrando ruta: " + path);

        // Rutas protegidas (ajústalas según tu proyecto)
        boolean isProductRoute = path.startsWith("/api/products");
        boolean isOrderRoute   = path.startsWith("/api/orders");
        boolean isPaymentRoute = path.startsWith("/api/payments");

        if (isProductRoute || isOrderRoute || isPaymentRoute) {
            // Extraer el token del header "Authorization"
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            System.out.println(">>> Header Authorization: " + authHeader);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                System.out.println(">>> No se encontró el token en la petición");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.substring(7);
            try {
                Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String role = claims.get("roles", String.class);
                System.out.println(">>> Token válido. Rol: " + role);

                // Validar permisos según el rol
                if (isProductRoute && !role.equals("ROLE_USER") && !role.equals("ROLE_ADMIN")) {
                    System.out.println(">>> Acceso denegado a /api/products para rol: " + role);
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }

                if (isOrderRoute && !role.equals("ROLE_ADMIN")) {
                    System.out.println(">>> Acceso denegado a /api/orders para rol: " + role);
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }

                if (isPaymentRoute && !role.equals("ROLE_ADMIN")) {
                    System.out.println(">>> Acceso denegado a /api/payments para rol: " + role);
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }

                System.out.println(">>> Acceso permitido");
            } catch (Exception e) {
                System.out.println(">>> Token inválido: " + e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange);
}
}