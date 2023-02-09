package com.miracle.login.controller;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.miracle.login.beans.ERole;
import com.miracle.login.beans.RefreshToken;
import com.miracle.login.beans.Role;
import com.miracle.login.beans.User;
import com.miracle.login.exception.TokenRefreshException;
import com.miracle.login.jwt.JwtUtils;
import com.miracle.login.jwt.RefreshTokenService;
import com.miracle.login.jwt.UserDetailsImpl;
import com.miracle.login.jwt.payload.JwtResponse;
import com.miracle.login.jwt.payload.LoginRequest;
import com.miracle.login.jwt.payload.MessageResponse;
import com.miracle.login.jwt.payload.PasswordRequest;
import com.miracle.login.jwt.payload.SignupRequest;
import com.miracle.login.jwt.payload.TokenRefreshRequest;
import com.miracle.login.jwt.payload.TokenRefreshResponse;
import com.miracle.login.repository.RoleRepository;
import com.miracle.login.repository.UserRepository;
import com.miracle.login.service.UserService;

import io.swagger.annotations.ApiParam;


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
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	UserService userService;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		String jwt = jwtUtils.generateJwtToken(userDetails);
		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
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
		if(match==true) {
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
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
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
		return new ResponseEntity<List<Role>>(role , new HttpHeaders(), HttpStatus.OK);
	}
	@GetMapping("/roles/{id}")
	public ResponseEntity<Optional<User>> getAllRolesFromId(@ApiParam(value = "Id", required = true) @PathVariable("id") String id){
		Optional<User> roles = userService.getAllRolesFromId(id);
		return new ResponseEntity<Optional<User>>(roles , new HttpHeaders(), HttpStatus.OK);
	}
	
	@GetMapping("/userinfo/{id}")
	public ResponseEntity<Optional<User>> getUserInfo(@ApiParam(value = "Id", required = true) @PathVariable("id") String id){
		Optional<User> userinfo = userService.getUserInfo(id);
		return new ResponseEntity<Optional<User>>(userinfo,new HttpHeaders(), HttpStatus.OK);
	}
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/userslist")
	public ResponseEntity<List<User>> getAllUsers(){
		List<User> users = userService.getAllUsers();
		return new ResponseEntity<List<User>>(users , new HttpHeaders(), HttpStatus.OK);
	}
    @PutMapping("/edituser")
    public ResponseEntity<?> editUser(@RequestBody User users){
        try {
            Optional<User> user= userRepository.findById(users.getId());
           if (users.getName() !=null)
               user.get().setName(users.getName());
           if (users.getEmail() !=null)
        	   user.get().setEmail(users.getEmail());
           if (users.getPhone() !=null)
        	   user.get().setPhone(users.getPhone());
           if (users.getUsername() !=null)
        	   user.get().setUsername(users.getUsername());

            userRepository.save(user.get());
            return ResponseEntity.ok(new MessageResponse("Successfully account updated"));
        }catch (Exception e){
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }

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

