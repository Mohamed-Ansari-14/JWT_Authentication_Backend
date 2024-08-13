package com.jwt.JwtAuthentication.payload.request;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SignupRequest {

	@NotBlank
	@Size(max = 50)
	@Email(regexp = "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,3}")
	private String username;
	
	private Set<String> role;
	
	@NotBlank
	@Size(max = 40)
	private String password;

	public SignupRequest(Set<String> role) {
		this.role = role;
	}
}
