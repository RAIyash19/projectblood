package com.example.demo.repository;

import java.util.List;

//import org.hibernate.mapping.List;
import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.PatientDetails;

public interface PatientDetailsRepository extends JpaRepository<PatientDetails, Integer>{

	public List<PatientDetails> findByEmail(String email);

	public List<PatientDetails> findByStatus(byte status);
	
	
	public List<PatientDetails> findByEmailAndStatus(String email, byte status);
	

	
}
