package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.entity.DonorDetails;

@Repository
public interface DonorDetailsRepository extends JpaRepository<DonorDetails, Integer> {
	
	
	public List<DonorDetails> findByEmail(String email);
	
	public List<DonorDetails> findByStatus(byte status);
	
	public List<DonorDetails> countByStatus(byte status);
	
	
	public List<DonorDetails> findByEmailAndStatus(String email, byte status);
	
	
	//public List<RegistrationDetails> findByEmail(String email);
}
