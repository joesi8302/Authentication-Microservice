package com.ecom.config;

import com.ecom.model.Session;
import com.ecom.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalTime;
import java.util.Collection;
import java.util.Set;

@Service
public class SessionAuthenticationFilter extends OncePerRequestFilter {


    @Autowired
    SessionService sessionService;

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String sessionId = getSessionId(request);
        System.out.println("AUTHENTICATING SESSION");
        if(StringUtils.hasText(sessionId) && validateToken(sessionId)){
            Session foundSession = sessionService.getSession(Integer.valueOf(sessionId));

            String username = foundSession.getUserDetails();

            UserDetails user = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,null,
                    user.getAuthorities());
            System.out.println(user.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);


        }
        else{
            clearAuthTokenCookie(response);
//            response.sendRedirect("/");
            System.out.println("Validation failed. Clearing authentication token.");
        }
        filterChain.doFilter(request,response);
    }




    private boolean validateToken(String sessionId){
        Session foundSession = sessionService.getSession(Integer.valueOf(sessionId));
        if(foundSession != null){
            return foundSession.getExpirationTime().isAfter(LocalTime.now());
        }

        return false;
    }

    private void clearAuthTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("SESSION-ID", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);  // Immediately expires the cookie
        response.addCookie(cookie);
    }



    private String getSessionId(HttpServletRequest request){

        Cookie[] cookies = request.getCookies();
        String bearerToken = "";
        if(cookies != null){
            for(Cookie cookie : cookies){
                if("SESSION-ID".equals(cookie.getName())){
                    System.out.println(cookie);
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}
