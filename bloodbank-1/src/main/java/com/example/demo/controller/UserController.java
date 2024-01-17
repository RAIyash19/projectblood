package com.example.demo.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.configuration.CustomUserDetail;
import com.example.demo.entity.DonorDetails;
import com.example.demo.entity.PatientDetails;
import com.example.demo.entity.RegistrationDetails;
import com.example.demo.service.RegistrationDetailsService;
import com.example.demo.service.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
@RequestMapping("/user")
public class UserController {
	
	@Autowired
	private UserService loginService;
	
	@Autowired
	private RegistrationDetailsService registerService;
	
	
//	@GetMapping("/verifyUserLogin")//1
//	public String verifyLogin(@ModelAttribute("received") RegistrationDetails received, HttpSession session, Model model) {
//        int status = loginService.verifyLogin(received);
//
//        if (status == 1) {
//            // If login is successful, return the Thymeleaf template name for redirection
//            //return "redirect:/dashboard_u";
//        	  //return "userDashboard";
//        	session.setAttribute("userEmail", received.getEmail());
//        	return "redirect:/userHome";
//        } 
//        else if (status == 0) {
//        	model.addAttribute("message", "Email is invalid");
//        }
//        else {
//            // If login fails, add an error message to the model and stay on the login page
//            model.addAttribute("error", "Invalid password");
//        }
//        return "userLogin"; 
//    }
	
//	@PostMapping("/sendOTP/{email}")
//	@ResponseStatus(HttpStatus.OK)
//	@ResponseBody
//	public void sendOtp(@PathVariable("email") String email, Model model) {
//		int status = loginService.sendOtp(email);
//		if (status ==1) {
//			model.addAttribute("message", "User aleady existing");
//		}
//		System.out.println("request mapped " + email);
//		
//	}
	

	
//	@PostMapping("/resetPassword")
////	public String resetPassword(@PathVariable("email") String email,@PathVariable("otp") int otp,@PathVariable("password") String password, Model model) {
//	public String resetPassword(@ModelAttribute("detail") RegistrationDetails detail, Model model) {
//		
//		int status = loginService.resetPassword(detail.getEmail(), detail.getOtp(),detail.getPassword(), model);
//		if (status==1) 
//			return "redirect:/userLogin";
//		return "foregetPassword";
//	}
	
	
	@GetMapping("/viewProfileDetail")
	public String viewProfileDetail(HttpSession session, Model model) {
	    // Retrieve the email from the session
	   // String adminEmail = (String) session.getAttribute("loggedInUserEmail");
	    CustomUserDetail user = (CustomUserDetail) session.getAttribute("user");
	    String email = user.getEmail();
	    
	    System.out.println(email);

	    if (email == null) {
	        // Handle the case where the admin is not logged in
	        return "redirect:/adminLogin";  // Redirect to the admin login page or handle appropriately
	    }

	    // Add logic to fetch user details based on the admin's email
	    List<RegistrationDetails> userDetails = loginService.getProfileDetails(email);
	    for(RegistrationDetails a:userDetails) {
	    	System.out.println(a.getBloodGroup());
	    	System.out.println(a.getCity());
	    	System.out.println(a.getFirstname());
	    }

	    // Add the user details to the model
	    model.addAttribute("user", userDetails);

	    // Return the Thymeleaf template name
	    return "userProfile";
	}
	
	
	
	
	
	
	@GetMapping("/viewProfileDetails/{email}")//1
	public List<RegistrationDetails> viewProfileDetails(@PathVariable("email") String email) {
		return loginService.getProfileDetails(email);
	}
	
	@PostMapping("/updateUserDetails")//1
	public String updateProfile(@ModelAttribute("received") RegistrationDetails received, Model model) {
		 System.out.println("update");
		 System.out.println(received);
		 loginService.updateProfile(received);
		 model.addAttribute("userData", received);
		 model.addAttribute("userUpdate", "Details updated successfully");
		 return "redirect:/user/viewProfileDetail";
	}
	
//	@GetMapping("/getDonationAndBloodCount/{email}")
//	@ResponseStatus(HttpStatus.OK)
//	@ResponseBody
//	public void getDonationAndBloodCount(@PathVariable("email") String email) {
//		
//		int bloodRequests = loginService.getBloodRequestsCount(email);
//		int donationRequests = loginService.getDonationCount(email);
//		
//	}
	
	@GetMapping("/viewBloodRequestDetails")//1
	public String viewBloodRequestsDetails(HttpSession session,Model model) {
		if (session.getAttribute("userEmail") == null) {
            // Session is valid, return the Thymeleaf template name for the user home page
            return "userLogin";
        }
		
		String email = (String) session.getAttribute("userEmail");
		List<PatientDetails> list = loginService.getBloodRequestsDetails(email);
		model.addAttribute("bloodRequestHistory", list);
		return "userBloodRequestHistory";
	}
	
	@GetMapping("/viewDonateRequestDetails")//1------------------------------------------------------
	public String getDonateRequestsDerails(HttpSession session, Model model) {
		if (session.getAttribute("userEmail") == null) {
            // Session is valid, return the Thymeleaf template name for the user home page
            return "userLogin";
        }
		String email = (String) session.getAttribute("userEmail");
			List<DonorDetails> list = loginService.getDonateRequestsDetails(email);
			
			for(DonorDetails detail:list) {
				System.out.println(detail.toString());
			}
			model.addAttribute("donationRequestHistory", list);
			return "userDonationRequestHistory";
	}
	
	@GetMapping("/viewAcceptedBloodDonationCount/{email}")//1
	public String getBloodDonationCount(@PathVariable("email") String email) {
		 loginService.findBloodDonationsCount(email);
		 return null;
	}
	
	@GetMapping("/viewAcceptedBloodRequestCount/{email}") // acepted requests
	public String getBloodRequestCount(@PathVariable("email") String email) {
		 loginService.findBloodRequestsCount(email);
		 return null;
	}
	
	@PostMapping("/bloodDonationRequest")//1
	public String donateRequest(@ModelAttribute("received") DonorDetails received,HttpSession session, Model model) {
		if (session.getAttribute("userEmail") == null) {
            // Session is valid, return the Thymeleaf template name for the user home page
            return "userLogin";
        } 
//		System.out.println("donation request");
//		System.out.println(received.getDateOfDonation() + " " + received.getCity());
		int status = loginService.donateRequest(received);
		switch(status) {
		case 0:model.addAttribute("donateMessage", "Email not found");
		return "donationRequest";
		case 1:  model.addAttribute("donateMessage", "You are eligible to donate, request needs to be accepted by admin");
		return "userHome";
		case 2:model.addAttribute("donateMessage", "you are not allowed to Donate Blood, age should be minimum 18 years");
		return "donationRequest";
		case 3:model.addAttribute("donateMessage","Older people are not allowe to donate");
		return "donationRequest";
		case 4:
			model.addAttribute("donateMessage", "You can't make a request again without the last request getting verified");
			return "donationRequest";
		case 5:
			model.addAttribute("donateMessage", "Less than in 90 days period of time is not allowed to donate blood again");
			return "donationRequest";
			
		}
		System.out.println("donation request  "  + "  " + received.getEmail() + " " +  " " + received.getDateOfDonation());
		return "userHome";
	}
	
	@PostMapping("/bloodRequestSelf")  //1
	public String bloodRequestSelf(@ModelAttribute("received")  PatientDetails received,HttpSession session, Model model) {
		
		
		System.out.println("inside self");
		if (session.getAttribute("userEmail") == null) {
            // Session is valid, return the Thymeleaf template name for the user home page
            return "userLogin";
        } 
		System.out.println(received.getEmail()+ " " + received.getBloodGroup() + " " + received.getBloodUnits());
//		return "userHome";
		int status = loginService.bloodRequestSelf(received);
		if (status==0) {
			System.out.println("You can't made blood request again until the last request being verified");
			model.addAttribute("bloodRequestStatus", "You can't made blood request again until the last request being verified");
		}
		else if (status ==1)
			model.addAttribute("bloodRequestStatus", "Not allowed to take blood more than 5 units");
		else if (status == 2)
			model.addAttribute("bloodRequestStatus", "There is no enough blood in the Inventory");
		else {
			model.addAttribute("bloodRequestStatus", "Blood is available, admin has to accept your request");
			return "userHome";
		}
		return "bloodRequest";
	}
	

	@PostMapping("/bloodRequestOthers")  //1
	public String bloodRequestOthers(@ModelAttribute("received")  PatientDetails received,HttpSession session, Model model) {
		
		System.out.println("inside others");
		if (session.getAttribute("userEmail") == null) {
            // Session is valid, return the Thymeleaf template name for the user home page
            return "userLogin";
        } 
		
		System.out.println("mmmm : " + received.getEmail());
		System.out.println(received.getEmail()+ " " + received.getBloodGroup() + " " + received.getBloodUnits());
//		return "userHome";
		int status = loginService.bloodRequestOthers(received);
		if (status==0) {
			System.out.println("You can't made blood request again until the last request being verified");
			model.addAttribute("bloodRequestStatus", "You can't made blood request again until the last request being verified");
		}
		else if (status ==1)
			model.addAttribute("bloodRequestStatus", "Not allowed to take blood more than 5 units");
		else if (status == 2)
			model.addAttribute("bloodRequestStatus", "There is no enough blood in the Inventory");
		else {
			model.addAttribute("bloodRequestStatus", "Blood is available, admin has to accept your request");
			return "userHome";
		}
		return "bloodRequest";
	}
	
	
	

}
