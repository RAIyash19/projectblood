package com.example.demo.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entity.RegistrationDetails;
import com.example.demo.repository.RegistrationDetailsRepository;

@Service
public class RegistrationDetailsService {
	
	@Autowired
	private RegistrationDetailsRepository repo;
	
	public String saveRegistrationDetails(RegistrationDetails detail) {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String passwd = passwordEncoder.encode(detail.getPassword());
		detail.setPassword(passwd);
		repo.save(detail);
		return "Registered successfully";
	}
	
	
	public RegistrationDetails updateUserProfile(RegistrationDetails user)
	{
		return repo.save(user);
	
	}
	
	
	public void deleteRegistrationDetail(String email) {
		List<RegistrationDetails> saved = getRegistrationDetailsByEmail(email);
		for(RegistrationDetails detail: saved) {
			repo.delete(detail);
		}
	}
	
	
	public List<RegistrationDetails> getRegistrationDetails() {
		return repo.findAll();
	}
	
	public Optional<RegistrationDetails> getRegistrationDetailsById(int id) {
		return repo.findById(id);
	}
	
	public List<RegistrationDetails> getRegistrationDetailsByEmail(String email) {
		return repo.findAllByEmail(email);
	}


	public List<RegistrationDetails> getRegistrationDetailsByRole(String role) {
		// TODO Auto-generated method stub
		return repo.findByRole(role);
	}
	
}
