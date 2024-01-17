package com.example.demo.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.entity.DonorDetails;
import com.example.demo.entity.Inventory;
import com.example.demo.repository.DonorDetailsRepository;

import jakarta.transaction.Transactional;

@Service
public class DonorDetailsService {
	
	@Autowired
	private DonorDetailsRepository repo;
	
	@Autowired
	private InventoryService inventoryrepo;
	
	public List<DonorDetails> getDonorDetails(){
		return repo.findAll();
	
	}
	
	public List<DonorDetails> findByemail(String email) {
        return repo.findByEmail(email);
	}
	
	public List<DonorDetails> getTotalDonationCount(){
		//byte a =0;
		//byte status=1;
		return repo.findByStatus((byte) 1);
		
		
		
	}
	
	
	
	
    @Transactional
    public List<DonorDetails> checkEligibility(List<DonorDetails> donors) {
        List<DonorDetails> eligible = new ArrayList<>();
        
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");  
        Date date = new Date();  
        String todayDate = formatter.format(date);

        for (DonorDetails donorlist : donors) {
            String donationDate = donorlist.getDateOfDonation();
            long days = findDifference(donationDate, todayDate);

            if (days > 90) {
                String id = donorlist.getEmail();
                System.out.println(id);
                //repo.deleteByBloodId(id);
               // deletedItems.add(donorlist);
                eligible.add(donorlist);
            }
        }

        return eligible;
    }

    static long findDifference(String donationDate, String todayDate) {
        long daysDifference = 0;
        
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date date1 = sdf.parse(donationDate);
            Date date2 = sdf.parse(todayDate);
            long timeDifference = date2.getTime() - date1.getTime();
            daysDifference = (timeDifference / (1000 * 60 * 60 * 24)) % 365;
            System.out.println("The Blood sample is " + daysDifference + " days older.");
        } catch (Exception e) {
            System.out.print(e);
        }
        
        return daysDifference;
    }

	public DonorDetails saveDonorDetails(DonorDetails detail) {
		return repo.save(detail);
	}
	
	// for the purpose of Admin
	public List<DonorDetails> getDonorsDetails() {
		return repo.findAll();
	}
	
	// for the purpose of User
	public List<DonorDetails> getDonorsDetailsByEmail(String email) {
		return repo.findByEmail(email);
	}
	
	public List<DonorDetails> getDonordetailsByStatus(byte status){
		return repo.findByStatus(status);
	}
	
	 public DonorDetails updateStatus(DonorDetails detail) {
		return repo.save(detail);
	}
	 
	 public List<DonorDetails> getDonorDetailsByEmailAndStatus(String email, byte status) {
		 return repo.findByEmailAndStatus(email, status);
	 }
	 
//	 public DonorDetails saveDetails(DonorDetails detail) {
//		 return inventoryrepo.updateStatus(detail);
//	 }
	 
	 
	 
	 
	 
//	 public Inventory convertDonorDetailsToInventory(DonorDetails donorDetails) {
//	        Inventory inventory = new Inventory();
//	        // Set properties from donorDetails to inventory
//	        //inventory.setStatus(donorDetails.isStatus());
//	        inventory.setBloodGroup(donorDetails.getBloodGroup());
//	        inventory.setQuantity(1);	        // Set other properties as needed
//	        return inventory;
//	    }
	 
	 
	 
	 
	 
	 
	 
	
	public List<DonorDetails> acceptDonationRequest(){
		List<DonorDetails> saved= getDonordetailsByStatus((byte) 0);
		List<DonorDetails> donors = new ArrayList<>();
		for (DonorDetails detail: saved) {
			if(detail.getStatus()==0) {
				donors.add(detail);
				//saveDonorDetails(detail);
				
				//detail.setStatus();
				updateStatus(detail);
//				Inventory inventory = convertDonorDetailsToInventory(detail);
//				inventoryrepo.updateStatus(inventory);
				
				
			}
		}
		
		return donors;
		
		
	}
	

    
    

}
