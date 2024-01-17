package com.example.demo.service;


import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;

import com.example.demo.emailService.SendEmailService;
import com.example.demo.entity.BloodGroupDetails;
import com.example.demo.entity.DonorDetails;
import com.example.demo.entity.Inventory;
import com.example.demo.entity.PatientDetails;
import com.example.demo.entity.RegistrationDetails;


@Service
public class AdminService {

	
	@Autowired
	private RegistrationDetailsService service;
	
	@Autowired
	private DonorDetailsService donorService;
	
	@Autowired
	private InventoryService inventoryService;
	
	@Autowired
	private PatientDetailsService patientService;
	
	@Autowired
	private SendEmailService emailService;
	
//	public byte verifyLogin(RegistrationDetails received) {
//		
//		BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
//		System.out.println("yyyyyyy");
//		List<RegistrationDetails> saved = service.getRegistrationDetailsByRole("admin"); //received.getRole("admin");
//		System.out.println(saved);
//		for (RegistrationDetails detail: saved) {
//			System.out.println(detail);
//			if (detail.getEmail().equals(received.getEmail())) {
//				System.out.println(detail.getEmail());
//				
//				if (bcrypt.matches(received.getPassword(), detail.getPassword()))
//				{
//					return 1; // Successful admin login
//				}
//				else 
//					return -1; // Password incorrect
//			}
//			else {
//				return 0;
//		}
//		 // Details not found
//	}
//		return 0;
//	}
	public byte verifyLogin(RegistrationDetails received) {
	    BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
	    System.out.println(received.getEmail());
	    
	    List<RegistrationDetails> saved = service.getRegistrationDetailsByRole("admin");

	    System.out.println(saved);

	    for (RegistrationDetails detail : saved) {
	        System.out.println(detail);

	        if (detail.getEmail().equals(received.getEmail())) {
	            System.out.println(detail.getEmail());

	            if (bcrypt.matches(received.getPassword(), detail.getPassword())) {
	                return 1; // Successful admin login
	            } else {
	                return -1; // Password incorrect
	            }
	        }
	    }

	    // If no matching email is found
	    return 0;
	}

	
	public List<DonorDetails> getDonationRequests() {
		return donorService.getDonordetailsByStatus((byte) 0);
	}
	
	public List<DonorDetails> getDonationHistory(){
		return donorService.getDonorDetails();
	}
	
	public List<PatientDetails> getBloodRequestsHistory(){
		return patientService.getBloodRequestsHistory();
	}
	
	public List<PatientDetails> getBloodRequest(){
		return patientService.getBloodRequestDetailsByStatus((byte) 0);
	}
	//public List<PatientDetails> getDo

// reject status maake it null funcvtion
	
	public String acceptDonationRequest(String email) {
		//String email=received.getEmail();
		List<DonorDetails> saved = donorService.getDonorsDetailsByEmail(email);
		for (DonorDetails detail:saved) {
			if (detail.getStatus()==1) {
				return "why are you accepting again and again, go and some other work";
			}
			if (detail.getStatus() == 0) {
				detail.setStatus((byte) 1);
			}
			Inventory inv = new Inventory();
			inv.setBloodGroup(detail.getBloodGroup());
			inv.setDateOfDonation(detail.getDateOfDonation());
			inv.setQuantity(1);
			inventoryService.saveInventory(inv);
			donorService.saveDonorDetails(detail);
		}
		//
//		emailService.sendEmail(email,"this is to inform you", "your blood donation request is accepted");
		return "Donation request accepted for the user with email " ;
	}


	public  List<PatientDetails> viewBloodRequest() {
		return patientService.getPatientDetailsByStatus((byte) 0);
	}


	public String acceptBloodRequest(String email) {
//		String email=received.getEmail();
		List<PatientDetails> saved = patientService.getPatientsDetailsByEmail(email);
		
		
		for (PatientDetails detail: saved) {
			if (detail.getStatus()==1) {
				return "why are you accepting again and again, go and some other work";
			}
			
			if (detail.getStatus() == 0)
				detail.setStatus((byte) 1);
			
			
			int units = detail.getBloodUnits();
			List<Inventory> saved1 = inventoryService.getInventoryDetailsByBloodGroup(detail.getBloodGroup());
			
			for (Inventory inv:saved1) {
				if (inv.getQuantity()!= 0) {
					units--;
					inventoryService.deleteInventory(inv);
					if (units == 0)
						break;
				}	
			}
			
			patientService.savePatientDetails(detail);
		}
//		emailService.sendEmail(email,"this is to inform you", "your blood request is accepted");
		return "Given "  + "units or blood successfully";
	}


	public String rejectDonationRequest(String email) {
		//String email=detail.getEmail();
		List<DonorDetails> saved= donorService.getDonorsDetailsByEmail(email);
		List<DonorDetails> donors = new ArrayList<>();
		for (DonorDetails detail1: saved) {
			if(detail1.getStatus()==0) {
				//donors.add(detail1);
				//saveDonorDetails(detail);
				
				detail1.setStatus((byte) -1);
				donorService.updateStatus(detail1);
//				Inventory inventory = convertDonorDetailsToInventory(detail);
//				inventoryrepo.updateStatus(inventory);
				
				return " Blood Donatio request rejected";
			}
			
		}
		emailService.sendEmail(email,"this is to inform you", "your blood donation request is rejected");
		
		return "no Blood Donation request is there to reject";
		
	}


	public String rejectBloodRequest(String email) {
		//String email=detail.getEmail();
		List<PatientDetails> saved= patientService.getPatientsDetailsByEmail(email);
		//List<DonorDetails> donors = new ArrayList<>();
		for (PatientDetails detail1: saved) {
			if(detail1.getStatus()==0) {
				//donors.add(detail1);
				//saveDonorDetails(detail);
				
				detail1.setStatus((byte) -1);
				patientService.updateStatus(detail1);
//				Inventory inventory = convertDonorDetailsToInventory(detail);
//				inventoryrepo.updateStatus(inventory);
				
				return "Blood request rejected";
			}
			
		}
		emailService.sendEmail(email,"this is to inform you", "your blood request is rejected");
		return "no Blood request is there to reject";
	}
	
	public RegistrationDetails updateUserProfile(RegistrationDetails user)
	{
		List<RegistrationDetails> saved = service.getRegistrationDetailsByEmail(user.getEmail());
		RegistrationDetails obj = new RegistrationDetails();
		for(RegistrationDetails detail: saved) {
			detail.setBloodGroup(user.getBloodGroup());
			detail.setCity(user.getCity());
			detail.setDateOfBirth(user.getDateOfBirth());
			detail.setEmail(user.getEmail());
			detail.setFirstname(user.getFirstname());
			detail.setGender(user.getGender());
			detail.setLastname(user.getLastname());
			
			service.updateUserProfile(detail);
		}
		return null;
		
	}


	
	public List<RegistrationDetails> getProfileDetails(RegistrationDetails detail) {
		
		List<RegistrationDetails> saved = service.getRegistrationDetailsByEmail(detail.getEmail());
		List<RegistrationDetails> data = new ArrayList<>();
		for(RegistrationDetails user :saved) {
			data.add(user);
		}
		
		return data;
		
	}
	
	
	public List<BloodGroupDetails> getDetail() {
	    List<BloodGroupDetails> bloodGroupDetailsList = new ArrayList<>();

	    bloodGroupDetailsList.add(new BloodGroupDetails("A+", inventoryService.getBloodCount("A+")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("A-", inventoryService.getBloodCount("A-")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("B+", inventoryService.getBloodCount("B+")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("B-", inventoryService.getBloodCount("B-")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("AB+", inventoryService.getBloodCount("AB+")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("AB-", inventoryService.getBloodCount("AB-")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("O+", inventoryService.getBloodCount("O+")));
	    bloodGroupDetailsList.add(new BloodGroupDetails("O-", inventoryService.getBloodCount("O-")));
	    
	    
	    System.out.println(bloodGroupDetailsList.get(0));
	    System.out.println(bloodGroupDetailsList.get(1));
	    System.out.println(bloodGroupDetailsList.get(3));

	    //model.addAttribute("bloodGroupDetailsList", bloodGroupDetailsList);

	    //return "bloodInventoryTable.html"; // Replace with the actual Thymeleaf template name
	    return bloodGroupDetailsList;
	}
	
	//@GetMapping("countStatusBloodRequest")
	  public int countBloodRequest(){
		  List<PatientDetails> saved = patientService.getTotalRequestCount();
		  int count = saved.size();
		  //List<Integer> countRequest= new ArrayList<>();
		  System.out.println(count);
		  return count;
		  
	  }
	
}
