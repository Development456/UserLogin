package com.miracle.login.beans;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import javax.validation.constraints.Email;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Data
@Document(collection = "user_details")
@JsonInclude(value = Include.NON_NULL)
public class User {
	@Id
	private String id;
	
	@Field("username")
	private String username;
	
	@Field("password")
	private String password;
	
	@Field("name")
	private String name;
	
	@Field("email")
	@Email
//	(regexp = "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,3}",
//            flags = Pattern.Flag.CASE_INSENSITIVE)
	private String email;
	
	@Field("phone")
	private String phone;
	
	@Field("wms_account_number")
	private String wmsAccountNumber;
	
	@DBRef
	private Set<Role> roles = new HashSet<>();
	
//	@DBRef
//	private List<RefreshToken> token = new ArrayList<>();
	
	public User(String username, String email, String name, String phone, String password) {
		    this.username = username;
		    this.email = email;
		    this.name= name;
		    this.phone=phone;
		    this.password = password;
	}

	
}

