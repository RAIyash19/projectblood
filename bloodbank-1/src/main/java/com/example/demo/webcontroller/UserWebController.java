package com.example.demo.webcontroller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.demo.configuration.CustomUserDetail;
import com.example.demo.controller.AdminController;
import com.example.demo.entity.BloodGroupDetails;
import com.example.demo.entity.LoggedInUser;
import com.example.demo.entity.RegistrationDetails;
import com.example.demo.service.AdminService;
import com.example.demo.service.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
public class UserWebController {
	
	 @Autowired
	 private HttpSession session;
	 
	 @Autowired
	 private AdminController adminService;
	 
	 @Autowired
	 private AdminService admin;
	 
	 @Autowired
	  private UserService userService;
	 
	@GetMapping("/") 
	public String home () {
		System.out.println("IN");
		return "index";
	}
//	@GetMapping("/login")
//	public String login() {
//		return "login";
//	}
	
	@GetMapping("/userLogin")
	public String userlogin() {
		return "userLogin";
	}
	
	@GetMapping("/dashboard_u" )
	public String userDashboard() {
		return "dashboard_u";
	}
	
	

	 @GetMapping("/userRegistration")
	    public String userRegistration() {
	        return "userRegistration";
	    }
	
	@GetMapping("/registrationStatus")
	public String registrationStatus() {
		return "registrationStatus";
	}
	
//	@GetMapping("/userHome")
//	public String userHome() {
//		return "userHome";
//	}
	@GetMapping("/forgetPassword")
	public String forgetPassword() {
		return "forgetPassword";
	}
	@GetMapping("/forgetPasswordadmin")
		public String forgetPasswordadmin() {
			return "forgetPasswordadmin";
		}
	
	
	
	
	
	
	@GetMapping("/adminLogin")
	public String adminLogin(){
	
		return "adminLogin";
	}
	
//	@GetMapping("/adminHome")
//	public String adminHome() {
//		return "adminHome";
//	}
	
	@GetMapping("/adminHome")
    public String adminHome(Model model, HttpSession session) {
		
//		RegistrationDetails user = (RegistrationDetails) session.getAttribute("user");
		CustomUserDetail user = (CustomUserDetail) session.getAttribute("user");
		String email = user.getEmail();
		System.out.println(email);
		
		 List<Integer> countDonor = adminService.countDonorsWithStatusOne();
         int a=countDonor.get(0);
         System.out.println(a);
         
         model.addAttribute("DonorCount", a);
         
         
         //totalrequest
         int b= admin.countBloodRequest();
         System.out.println(b);
         model.addAttribute("requestCount", b);
         
   
        
         List<BloodGroupDetails> bloodCount = admin.getDetail();
         model.addAttribute("bloodGroupDetailsList", bloodCount);
		
		 //String email = (String) session.getAttribute("loggedInUserEmail");

		    // Pass the user's email to the Thymeleaf template
		    model.addAttribute("email", email);
		 

        return "adminHome";
    }
	
	
	@GetMapping("/userHome")
	public String check(HttpSession session, Model model) {
		
	            // Session is valid, return the Thymeleaf template name for the user home page
			 CustomUserDetail user = (CustomUserDetail) session.getAttribute("user");
				String email = user.getEmail();
				System.out.println(email);
			 //String email= (String) session.getAttribute("userEmail");
			 	model.addAttribute("email", email);
			 	int donationCount=userService.findBloodDonationsCount(email);
			 	int bloodCount=userService.findBloodRequestsCount(email);
			 	
			 	model.addAttribute("donationCount", donationCount);
			 	model.addAttribute("bloodCount", bloodCount);
	            return "userHome";
		 
	        

	}
	
	
	
	
//	@GetMapping("/adminProfile")
//	public String adminProfile(Model model, HttpSession session) {
//String email = (String) session.getAttribute("loggedInUserEmail");
//		
//	    model.addAttribute("email", email);
//		return "adminProfile";
//	}
	
//	@PreAuthorize("hasRole('ADMIN')")
//	@GetMapping("/adminProfile")
//	public String adminProfile() {
//		System.out.println("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");
//		return "adminProfile";
//		
//	}
	
	
	@GetMapping("/adminfetch")
	public String adminfetch(Model model, HttpSession session) {
		String email = (String) session.getAttribute("loggedInUserEmail");
		
	    model.addAttribute("email", email);
		
		return "adminfetch";
	}
	@GetMapping("/profileDisplay")
	public String profileDisplay() {
		return "profileDisplay";
	}
	
	@GetMapping("/bloodDonationView")
	public String bloodDonationView() {
		return "bloodDonationView";
	}
	
	@GetMapping("/bloodDonationRequests")
	public String bloodDonationRequests() {
		return "bloodDonationRequests";
	}
	
	
	@GetMapping("/bloodRequestAdmin")
	public String bloodRequestAdmin() {
		return "bloodRequestAdmin";
	}
	
	
	@GetMapping("/bloodRequestsViews")
	public String bloodRequestsViews() {
		return "bloodRequestsViews";
	}
	
	@GetMapping("/bloodInventoryTable")
	public String bloodInventoryTable() {
		return "bloodInventoryTable";
	}
	
	@GetMapping("/bloodExpiry")
	public String bloodExpiry() {
		return "bloodExpiry";
	}
	
//	@PostMapping("/acceptDonationRequest")
//	public String acceptDonationRequest() {
//		return "acceptDonationRequest";
//	}
	
	
}
