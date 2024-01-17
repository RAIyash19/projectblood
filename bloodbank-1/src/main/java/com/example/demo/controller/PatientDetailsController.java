package com.example.demo.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.entity.PatientDetails;
import com.example.demo.service.PatientDetailsService;

@RestController
public class PatientDetailsController {
	
	@Autowired
	private PatientDetailsService service;
	
	
	@PostMapping("/addPatientDetails")
	public PatientDetails savePatientDetailsC(@RequestBody PatientDetails detail) {
		return service.savePatientDetails(detail);
	}
	
	@GetMapping("/getPatientsDetails")
	public List<PatientDetails> getPatientsDetailsC() {
		return service.getPatientDetails();
	}
	
//	@GetMapping("/getPatientDetailsByEmail/{email}")
//	public Optional<PatientDetails> getPatientDetailsByEmailC(@PathVariable String email) {
//		return service.getPatientDetailsByEmail(email);
//	}
	
	
}
