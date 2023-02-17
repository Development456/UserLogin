package com.miracle.login.controller;

import com.miracle.login.beans.*;
import com.miracle.login.exception.TokenRefreshException;
import com.miracle.login.jwt.JwtUtils;
import com.miracle.login.jwt.UserDetailsImpl;
import com.miracle.login.jwt.payload.*;
import com.miracle.login.repository.PasswordResetTokenRepository;
import com.miracle.login.repository.RoleRepository;
import com.miracle.login.repository.UserRepository;
import com.miracle.login.service.EmailService;
import com.miracle.login.service.RefreshTokenService;
import com.miracle.login.service.UserService;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	RefreshTokenService refreshTokenService;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;
	
	@Autowired
	PasswordResetTokenRepository resetTokenRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	UserService userService;
	
	@Autowired
	private EmailService emailService;
	

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		String jwt = jwtUtils.generateJwtToken(userDetails);
		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
	    RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());


		return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(),
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail(), 
												 roles));
	}
	@GetMapping("/settings")
	public String openSettings() {
		return "normal/settings";
	}
	@PutMapping("/changepassword")
	public ResponseEntity<?> changepassword(@Valid @RequestBody PasswordRequest passwordrequest, HttpSession session, Principal principal){
		String username = principal.getName();
		User loginUser = userService.findByName(username);
		boolean match = encoder.matches(passwordrequest.getCurrentPassword(), loginUser.getPassword());
		if(match) {
			loginUser.setPassword(encoder.encode(passwordrequest.getNewPassword()));
			User updatePasswordUser = userRepository.save(loginUser);
			if(updatePasswordUser!=null) {
				session.setAttribute("message","password changed");
			}else {
				session.setAttribute("message","something went wrong");
			}
			return ResponseEntity.ok(new MessageResponse("Password Changed Successfully!"));
		
		} else{
			session.setAttribute("message","current password incorrect");
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Password is incorrect"));
		}
//		return "redirect:/user/signin";
		

	}
	

	@PostMapping("/refreshtoken")
	public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
		String requestRefreshToken = request.getRefreshToken();

	    return refreshTokenService.findByToken(requestRefreshToken)
	        .map(refreshTokenService::verifyExpiration)
	        .map(RefreshToken::getUser)
	        .map(user -> {
	          String token = jwtUtils.generateTokenFromUsername(user.getUsername());
	          return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
	        })
	        .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
	            "Refresh token is not in database!"));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (Boolean.TRUE.equals(userRepository.existsByEmail(signUpRequest.getEmail()))) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
				 signUpRequest.getEmail(),
				 signUpRequest.getName(),
				 signUpRequest.getPhone(),
				 encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRoles();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
	@GetMapping("/roles")
	public ResponseEntity<List<Role>> getAllRoles(){
		List<Role> role = userService.getAllRoles();
		return new ResponseEntity<>(role , new HttpHeaders(), HttpStatus.OK);
	}
	@GetMapping("/roles/{id}")
	public ResponseEntity<Optional<User>> getAllRolesFromId(@ApiParam(value = "Id", required = true) @PathVariable("id") String id){
		Optional<User> roles = userService.getAllRolesFromId(id);
		return new ResponseEntity<>(roles , new HttpHeaders(), HttpStatus.OK);
	}
	
	@GetMapping("/userinfo/{id}")
	public ResponseEntity<Optional<User>> getUserInfo(@ApiParam(value = "Id", required = true) @PathVariable("id") String id){
		Optional<User> userinfo = userService.getUserInfo(id);
		return new ResponseEntity<>(userinfo,new HttpHeaders(), HttpStatus.OK);
	}
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/userslist")
	public ResponseEntity<List<User>> getAllUsers(){
		List<User> users = userService.getAllUsers();
		return new ResponseEntity<>(users , new HttpHeaders(), HttpStatus.OK);
	}
    @PutMapping("/edituser")
    public ResponseEntity<?> editUser(@RequestBody User users){
        try {
            Optional<User> user= userRepository.findById(users.getId());
           if(user.isPresent()) {
			   if (users.getName() != null)
				   user.get().setName(users.getName());
			   if (users.getEmail() != null)
				   user.get().setEmail(users.getEmail());
			   if (users.getPhone() != null)
				   user.get().setPhone(users.getPhone());
			   if (users.getUsername() != null)
				   user.get().setUsername(users.getUsername());
			   if (users.getRoles() != null)
				   user.get().setRoles(users.getRoles());
			   userRepository.save(user.get());
		   }
            return ResponseEntity.ok(new MessageResponse("Successfully account updated"));
        }catch (Exception e){
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }

    }
    @GetMapping("/forgotpassword")
    public ModelAndView displayForgotPasswordPage() {
    	return new ModelAndView("forgotPassword");
    }
    @PostMapping("/forgotpassword")
    public ModelAndView processForgotPasswordForm(ModelAndView modelAndView, @RequestParam(required=false) String email,HttpServletRequest request) {
		// Lookup user in database by e-mail
		User user = userService.findUserByEmail(email);

		if (user == null){
			modelAndView.addObject("errorMessage", "We didn't find an account for that e-mail address.");
		} else {
			
//			// Generate random 36-character string token for reset password 
//			User user = optional.get();
//			user.getToken().setToken(UUID.randomUUID().toString());
			PasswordResetToken resetTokens = new PasswordResetToken();
			resetTokens.setResetToken(UUID.randomUUID().toString());
			resetTokens.setUser(user);
			// Save token to database
			resetTokenRepository.save(resetTokens);
			
//			Map<String, Object> modelObj= new HashMap<>();
//			modelObj.put("resetTokens", resetTokens);
//			modelObj.put("user", user);
			

			String appUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();;
			
			// Email message
			SimpleMailMessage passwordResetEmail = new SimpleMailMessage();
			passwordResetEmail.setFrom("support@demo.com");
			passwordResetEmail.setTo(user.getEmail());
			passwordResetEmail.setSubject("Password Reset Request");
			passwordResetEmail.setText("To reset your password, click the link below:\n" + appUrl
					+ "/reset?token=" + resetTokens.getResetToken());
//	        modelObj.put("resetUrl", appUrl + "/forgotpassword?token=" + resetTokens.getResetToken());


			emailService.sendEmail(passwordResetEmail);

			// Add success message to view
			modelAndView.addObject("successMessage", "A password reset link has been sent to " + email);
		}

		modelAndView.setViewName("forgotPassword");
		return modelAndView;
    }
    @GetMapping("/reset")
    public ModelAndView getPasswordResetPage(@RequestParam(required=false) String resetTokens, ModelAndView model)
    {
        PasswordResetToken passwordResetToken = resetTokenRepository.findByResetToken(resetTokens);
        if(passwordResetToken == null)
        {
            model.addObject("error","Could not find reset token");
        }
        else if(passwordResetToken.isExpired())
        {
            model.addObject("error","Reset Token is expired");
        }
        else
        {
            model.addObject("token",passwordResetToken.getResetToken());
        }
        model.setViewName("resetpassword");
        return model;
        		
    }
	// Process reset password form
	@PostMapping("/reset")
	public ModelAndView setNewPassword(ModelAndView modelAndView, @RequestParam(required=false) String resetTokens, @RequestParam(required=false) String password, RedirectAttributes redir, HttpServletRequest request) {

		// Find the user associated with the reset token
//		Optional<User> user = userService.findByResetToken(requestParams.get("token"));
		PasswordResetToken passwordResetToken = resetTokenRepository.findByResetToken(resetTokens);
		Optional<User> user = Optional.ofNullable(passwordResetToken.getUser());

		// This should always be non-null but we check just in case
		if (user.isPresent()) {

			User resetUser = user.get();

			// Set new password
            resetUser.setPassword(encoder.encode(password));

			// Set the reset token to null so it cannot be used again
			passwordResetToken.
					setResetToken(null);

			// Save user
			userRepository.save(resetUser);

			// In order to set a model attribute on a redirect, we must use
			// RedirectAttributes
			redir.addFlashAttribute("successMessage", "You have successfully reset your password.  You may now login.");

			modelAndView.setViewName("redirect:signin");
			return modelAndView;

		} else {
			modelAndView.addObject("errorMessage", "Oops!  This is an invalid password reset link.");
			modelAndView.setViewName("resetPassword");
		}

		return modelAndView;
   }
//    @PostMapping
//    public String handlePasswordReset(HttpServletRequest request, ModelAndView model)
//    {
//        PasswordResetToken passwordResetToken = resetTokenRepository.findByResetToken(token);
//        User user = passwordResetToken.getUser();
//        String password = ServletUtil.getAttribute(request, "password");
//        String confirmPassword = ServletUtil.getAttribute(request, "confirmPassword");
//
//        user.setPassword(updatedPassword);
//        user.setPasswordConfirm(updatedPassword);
//        userRepository.save(user);
//        passwordResetTokenRepository.delete(passwordResetToken);
//
//        return "redirect:/login?resetSuccess";
//
//    }
   
//     Going to reset page without a token redirects to login page
	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ModelAndView handleMissingParams(MissingServletRequestParameterException ex) {
		return new ModelAndView("redirect:signin");
	}
    

//
//    @PostMapping("/delete")
//    public ResponseEntity<?> delete(@RequestBody User users){
//        try {
//            Optional<User> user= userRepository.findById(users.getId());
//            Optional<Role> roles= roleRepository.findByName(users.getRoles() == ROLE_ADMIN );
//            if(user.get().getRoles().stream().allMatch(y-> y.getId() ==roles.get().getId())){
//                return ResponseEntity.ok(new ApiResponse(false,"","Sorry!,you don't have permission to delete this account"));
//
//            }else {
//                user.get().setStatus(1);
//                userRepository.save(user.get());
//                return ResponseEntity.ok(new ApiResponse(true,"","Successfully account deleted"));
//
//            }
//        }catch (Exception e){
//            return ResponseEntity.ok(new ApiResponse(false,"",e.getMessage()));
//        }
//
//    }
	
}

