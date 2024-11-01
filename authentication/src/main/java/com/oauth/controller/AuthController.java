package com.oauth.controller;

import com.oauth.config.JWTGenerator;
import com.oauth.model.Session;
import com.oauth.model.UserDtls;
import com.oauth.service.SessionService;
import com.oauth.service.SessionServiceImpl;
import com.oauth.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalTime;
import java.util.Objects;

import static com.oauth.config.SecurityConstants.JWT_SECRET;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTGenerator jwtGenerator;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private SessionService sessionService;

    @PostMapping("/signin")
    public ResponseEntity<?> signin(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletResponse response){
        System.out.println("Signin page reached");
        System.out.println(username +  password);
        String token = "";

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            token = jwtGenerator.generateToken(authentication);
        } catch (BadCredentialsException e) {
            System.out.println("Authentication failed: Invalid credentials for " + username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Email or Password");
        }

        //Step 1: Validate User Credentials
        UserDtls user = userService.getUserByEmail(username);

        if(user == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Email or Password");
        }

        //Step 2: Generate Session ID


        //Step 3: Set session ID in a cookie



//        Cookie sessionCookie = new Cookie("AUTH-TOKEN", token);
//        sessionCookie.setHttpOnly(true);
//        sessionCookie.setPath("/");
//        sessionCookie.setMaxAge(24*60*80);
//        response.addCookie(sessionCookie);



        String redirectUrl = "http://localhost:8090/";
        if(Objects.equals(user.getRole(), "ROLE_ADMIN")){
            System.out.println("Sending to Admin");
            redirectUrl = "http://localhost:8090/admin/";
        }
        Session newSession = new Session();
        newSession.setExpirationTime(LocalTime.now().plusHours(1));
        newSession.setUserDetails(user.getEmail());
        Session savedSession = sessionService.saveSession(newSession);

        Cookie sessionCookie = new Cookie("SESSION-ID", savedSession.getId().toString());
        sessionCookie.setHttpOnly(true);
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(24*60*80);
        response.addCookie(sessionCookie);


        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header("Location",redirectUrl)
                .build();
    }

}
