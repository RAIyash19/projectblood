package com.example.demo.entity;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class PatientDetails {
	

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	private long id;
	private String email;
	private String firstname;
	private String lastname;
	private String gender;
	private String dateOfBirth;		// date of birth
	private int bloodUnits; 
	//private String bloodType;
	private String bloodGroup;
	private String city;
	private String reason;
	//private String Address;
	private String dateOfBlood; //date of blood request
	private byte status;
	
	
	public String getReason() {
		return reason;
	}
	public void setReason(String reason) {
		this.reason = reason;
	}
	public int getBloodUnits() {
		return bloodUnits;
	}
	public void setBloodUnits(int bloodUnits) {
		this.bloodUnits = bloodUnits;
	}
	public String getDateOfBlood() {
		return dateOfBlood;
	}
	public void setDateOfBlood(String dateOfBlood) {
		this.dateOfBlood = dateOfBlood;
	}
	
	
	
	public byte getStatus() {
		return status;
	}
	public void setStatus(byte status) {
		this.status = status;
	}
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getFirstname() {
		return firstname;
	}
	public void setFirstname(String firstname) {
		this.firstname = firstname;
	}
	public String getLastname() {
		return lastname;
	}
	public void setLastname(String lastname) {
		this.lastname = lastname;
	}
	public String getGender() {
		return gender;
	}
	public void setGender(String gender) {
		this.gender = gender;
		
	}
	
	public String getDateOfBirth() {
		return dateOfBirth;
	}
	public void setDateOfBirth(String dateOfBirth) {
		this.dateOfBirth = dateOfBirth;
	}
	
//	public String getBloodType() {
//		return bloodType;
//	}
//	public void setBloodType(String bloodType) {
//		this.bloodType = bloodType;
//	}
	public String getBloodGroup() {
		return bloodGroup;
	}
	public void setBloodGroup(String bloodGroup) {
		this.bloodGroup = bloodGroup;
	}
	public String getCity() {
		return city;
	}
	public void setCity(String city) {
		this.city = city;
	}
//	public String getAddress() {
//		return Address;
//	}
//	public void setAddress(String address) {
//		Address = address;
//	}
	

}
