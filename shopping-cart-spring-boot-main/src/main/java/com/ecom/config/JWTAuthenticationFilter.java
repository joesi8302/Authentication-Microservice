package com.ecom.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;
import java.util.Collection;
import java.util.Set;

@Service
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JWTGenerator jwtGenerator;

    @Autowired
    public UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public DaoAuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(userDetailsService);
//        authenticationProvider.setPasswordEncoder(passwordEncoder());
//
//        return authenticationProvider;
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = getJWTFromRequest(request);
        System.out.println("AUTHENTICATING TOKEN");
        if(StringUtils.hasText(token) && jwtGenerator.validateToken(token)){
            String username = jwtGenerator.getUsernameFromJWT(token);

            UserDetails user = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,null,
                    user.getAuthorities());
            System.out.println(user.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);


//            onSuccessfulJWTAuthentication(user, response);


        }
        else{
            clearAuthTokenCookie(response);
//            response.sendRedirect("/");
            System.out.println("JWT validation failed. Clearing authentication token.");
        }
        filterChain.doFilter(request,response);
    }

    private void onSuccessfulJWTAuthentication(UserDetails user, HttpServletResponse response) throws IOException {
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

        Set<String> roles = AuthorityUtils.authorityListToSet(authorities);

        if(roles.contains("ROLE_ADMIN"))
        {
            System.out.println("WE GOT AN ADMIN HERE");
            response.sendRedirect("/admin/");
        }else {
            response.sendRedirect("/");
        }
    }

    private void clearAuthTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("AUTH-TOKEN", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);  // Immediately expires the cookie
        response.addCookie(cookie);
    }



    private String getJWTFromRequest(HttpServletRequest request){

        Cookie[] cookies = request.getCookies();
        String bearerToken = "";
        if(cookies != null){
            for(Cookie cookie : cookies){
                if("AUTH-TOKEN".equals(cookie.getName())){
                    System.out.println(cookie);
                    return cookie.getValue();
                }
            }
        }



//        String bearerToken = request.getHeader("Authorization");
//        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
//            return bearerToken.substring(7, bearerToken.length());
//        }
        return null;
    }
}
