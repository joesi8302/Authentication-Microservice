package com.oauth.controller;

import com.oauth.model.*;

import com.oauth.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RestTemplate restTemplate;

	private static final String USER_SERVICE_URL = "http://localhost:8091/api/users/email/";

	@GetMapping("/")
	public String home(){
		return "user/home";
	}

	@PostMapping("/signin")
	public ResponseEntity<?> signin(
			@RequestParam String username,
			@RequestParam String password,
			HttpServletResponse response){

		//Step 1: Validate User Credentials
		UserDtls user = userService.getUserByEmail(username);

		if(user == null){
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Email or Password");
		}

		//Step 2: Generate Session ID


		//Step 3: Set session ID in a cookie

		Cookie sessionCookie = new Cookie("sessionId", "ABCSession");
		sessionCookie.setHttpOnly(true);
		sessionCookie.setPath("/");
		sessionCookie.setMaxAge(24*60*80);
		response.addCookie(sessionCookie);

		String redirectUrl = "http://localhost:8090";
		String sessionId = "ABCSession";
		return ResponseEntity.status(HttpStatus.FOUND)
				.header("Location",redirectUrl)
				.header("sessionId", sessionId)
				.build();
	}




}
