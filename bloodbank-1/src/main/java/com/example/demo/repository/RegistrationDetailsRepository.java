package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.RegistrationDetails;

public interface RegistrationDetailsRepository  extends JpaRepository<RegistrationDetails, Integer>{

	public RegistrationDetails findByEmail(String email);
	public List<RegistrationDetails> findAllByEmail(String email);
	
	public List<RegistrationDetails> findByRole(String role);
}
