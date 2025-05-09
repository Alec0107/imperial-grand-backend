package com.imperialgrand.backend.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.imperialgrand.backend.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.jwt.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Extract JWT from the Authorization header
        String authorizationHeader = request.getHeader("Authorization");
        String jwtToken = null;

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            System.out.println("Accessing public endpoints....");
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authorizationHeader.substring(7);

        try{
            if(jwtToken != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // load userEmail from db
                UserDetails userDetails = jwtService.validateAndLoadUserFromToken(jwtToken);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            filterChain.doFilter(request, response);
        }catch (InvalidJwtTokenException ex){
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> map = new HashMap<>();
            map.put("message", ex.getMessage());
            map.put("status", HttpStatus.UNAUTHORIZED.value());
            String jsonErrorResponse = objectMapper.writeValueAsString(map);

            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            response.getWriter().write(jsonErrorResponse);
        }
    }

}
