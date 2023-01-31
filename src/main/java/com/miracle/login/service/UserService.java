package com.miracle.login.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.miracle.login.beans.Role;
import com.miracle.login.beans.User;
import com.miracle.login.repository.RoleRepository;
import com.miracle.login.repository.UserRepository;

@Service
@Transactional
public class UserService implements UserServiceImpl{
	 @Autowired
	 private UserRepository userRepository;
	 
	 @Autowired
	 private RoleRepository roleRepository;
	 
	 public User findUserByEmail(String email) {
	        return userRepository.findByEmail(email);
	 }
	 
	@Override
	public List<Role> getAllRoles() {
			
		return roleRepository.findAll();
			
	}

	@Override
	public List<User> getAllUsers() {
		// TODO Auto-generated method stub
		return userRepository.findAll();
	}
	public Optional<User> getUserInfo(String id){
		return userRepository.findById(id);
	}
}

