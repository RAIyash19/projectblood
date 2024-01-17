package com.example.demo.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class DonorDetails {
	
	@Id
	@GeneratedValue(strategy=GenerationType.SEQUENCE)
	private int id;
	
	private String email;
	
	private String firstname;
	private String lastname;
	private String gender;
	//private String bloodType;
	private String bloodGroup;
	private String dateOfBirth;
	private String city;
//	private String street;
//	private String state;
//	private String pincode;
	private String dateOfDonation;
	private String timeSlot;
	
	
	private byte status;
	private String units;
	
	
	
	
public String getUnits() {
		return units;
	}
	public void setUnits(String units) {
		this.units = units;
	}
		public String getTimeSlot() {
		return timeSlot;
	}
	public void setTimeSlot(String timeSlot) {
		this.timeSlot = timeSlot;
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
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

	
	
	public String getDateOfBirth() {
		return dateOfBirth;
	}
	public void setDateOfBirth(String dateOfBirth) {
		this.dateOfBirth = dateOfBirth;
	}
	public String getCity() {
		return city;
	}
	public void setCity(String city) {
		this.city = city;
	}
	
	public String getDateOfDonation() {
		return dateOfDonation;
	}
	public void setDateOfDonation(String dateOfDonation) {
		this.dateOfDonation = dateOfDonation;
	}
	public byte getStatus() {
		return status;
	}
	public void setStatus(byte status) {
		this.status = status;
	}
	@Override
	public String toString() {
		return "DonorDetails [id=" + id + ", email=" + email + ", firstname=" + firstname + ", lastname=" + lastname
				+ ", gender=" + gender + ", bloodGroup=" + bloodGroup + ", dateOfBirth=" + dateOfBirth + ", city="
				+ city + ", dateOfDonation=" + dateOfDonation + ", status=" + status + ", units=" + units + "]";
	}
	
	
//	public String getStreet() {
//		return street;
//	}
//	public void setStreet(String street) {
//		this.street = street;
//	}
//	public String getState() {
//		return state;
//	}
//	public void setState(String state) {
//		this.state = state;
//	}
//	public String getPincode() {
//		return pincode;
//	}
//	public void setPincode(String pincode) {
//		this.pincode = pincode;
//	}
//	
	
	
	

}
