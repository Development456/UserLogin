package com.miracle.login.service;

import java.util.List;
import java.util.Optional;

import com.miracle.login.beans.Role;
import com.miracle.login.beans.User;

public interface UserServiceImpl {

	public User findUserByEmail(String email);
	  
	public Optional<User> findByResetToken(String token);

	public List<Role> getAllRoles();

	public List<User> getAllUsers();

	public Optional<User> getUserInfo(String id);

	public User findByName(String username);

	public Optional<User> getAllRolesFromId(String id); 
}
