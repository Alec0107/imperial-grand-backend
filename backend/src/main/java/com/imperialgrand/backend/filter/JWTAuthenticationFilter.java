package com.imperialgrand.backend.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.imperialgrand.backend.jwt.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.jwt.JwtGeneratorService;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtGeneratorService jwtService;
    private final Logger logger = Logger.getLogger(JWTAuthenticationFilter.class.getName());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        // For checking endpoint whether to decide to skip it or not
        String path = request.getServletPath();
        if(path.equals("/api/v1/auth/refresh-token") || path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/register") || path.equals("/api/v1/auth/verify")
                || path.equals("/api/v1/auth/resend-verification") || path.equals("/api/v1/auth/inbox-resend-verification") || path.equals("/api/v1/auth/verify-email")
                || path.equals("/api/v1/auth/forgot-password") || path.equals("/api/v1/auth/reset-password") || path.equals("/api/v1/auth/reset-password/")
                || path.equals("/api/v1/auth/reset-password/validate") || path.equals(("/api/v1/contact"))){
            logger.info("Endpoints skipped");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract token from HttpOnly cookie
        String accessJwtToken = null;
        if(request.getCookies() != null){
            for(Cookie cookie : request.getCookies()){
                if(cookie.getName().equals("access-token")){
                    accessJwtToken = cookie.getValue();
                    break;
                }
            }
        }

//        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
//            System.out.println("Accessing public endpoints....");
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        jwtToken = authorizationHeader.substring(7);

        if(accessJwtToken == null){
            logger.info("No access token found");
            exceptionSendBuilder("Access token is missing or expired.", response);
            return;
        }

        try{
            if(SecurityContextHolder.getContext().getAuthentication() == null) {
                // load userEmail from db
                UserDetails userDetails = jwtService.validateAccessToken(accessJwtToken);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            filterChain.doFilter(request, response);
        }catch (InvalidJwtTokenException ex){
            exceptionSendBuilder(ex.getMessage(), response);
        }catch(EmailNotFoundException ex) {
            exceptionSendBuilder(ex.getMessage(), response);
        } catch (Exception ex) {
            exceptionSendBuilder(ex.getMessage(), response);
        }
    }

    private void exceptionSendBuilder(String exceptionMessage, HttpServletResponse response) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> map = new HashMap<>();
        map.put("message", exceptionMessage);
        map.put("status", HttpStatus.UNAUTHORIZED.value());
        String jsonErrorResponse = objectMapper.writeValueAsString(map);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write(jsonErrorResponse);
    }

}
