package com.example.demo.configuration;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.demo.entity.RegistrationDetails;


public class CustomUserDetail implements UserDetails {
	
	private static final long serialVersionUID = 1L;
	private RegistrationDetails user;
	
	public CustomUserDetail(RegistrationDetails user) {
		this.user = user;
	}
	

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return List.of(() -> user.getRole());
	}

	public String getFirstname() {
		return user.getFirstname();
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}
	
//	public String getRole() {
//		return user.getRole();
//	}
//	
//	public int getOtp() {
//		return user.getOtp();
//	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return user.getLastname();
	}

	public String getEmail() {
		// TODO Auto-generated method stub
		return user.getEmail();
	}

	
	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}
	


}
