package com.example.demo.entity;

public class BloodGroupDetails {
    private String bloodGroup;
    private int count;

    // Constructors, getters, setters, and other methods as needed

    // Example constructor:
    public BloodGroupDetails(String bloodGroup, int count) {
        this.bloodGroup = bloodGroup;
        this.count = count;
    }

	@Override
	public String toString() {
		return "BloodGroupDetails [bloodGroup=" + bloodGroup + ", count=" + count + "]";
	}

	public String getBloodGroup() {
		return bloodGroup;
	}

	public void setBloodGroup(String bloodGroup) {
		this.bloodGroup = bloodGroup;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}
    
    
}

