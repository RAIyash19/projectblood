package com.example.demo.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;



@Entity
@Table(name = "blood_inventory")
public class Inventory {
	
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	private int bloodId;
	//private String BloodType;
	private String bloodGroup;
	private String dateOfDonation;
	private Integer quantity;
	
	
//	public String getBloodType() {
//		return BloodType;
//	}
//	public void setBloodType(String bloodType) {
//		BloodType = bloodType;
//	}
	
	public int getBloodId() {
		return bloodId;
	}
	public void setBloodId(int bloodId) {
		this.bloodId = bloodId;
	}
	public Integer getQuantity() {
		return quantity;
	}
	public void setQuantity(Integer quantity) {
		this.quantity = quantity;
	}
	
	
	public String getBloodGroup() {
		return bloodGroup;
	}
	public void setBloodGroup(String bloodGroup) {
		this.bloodGroup = bloodGroup;
	}
	public String getDateOfDonation() {
		return dateOfDonation;
	}
	public void setDateOfDonation(String dateOfDonation) {
		this.dateOfDonation = dateOfDonation;
	}
	@Override
	public String toString() {
		return "Inventory [bloodId=" + bloodId + ", bloodGroup=" + bloodGroup + ", dateOfDonation=" + dateOfDonation
				+ ", quantity=" + quantity + "]";
	}
	
	
	
}
