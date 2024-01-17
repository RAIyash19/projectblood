package com.example.demo.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.example.demo.entity.RegistrationDetails;
import com.example.demo.service.RegistrationDetailsService;
import com.example.demo.service.UserService;

@Controller
public class RegistrationDetailsController {

	@Autowired
	private RegistrationDetailsService service;
	@Autowired 
	private UserService userService;
	
	@PostMapping("/register")  //1
	public String saveDetail(@ModelAttribute("detail") RegistrationDetails detail, Model model) {
	
		boolean status=userService.checkEmailExistance(detail);
		if(status) 
			return "userLogin";
//		detail.setRole("user");
		List<RegistrationDetails> saved = service.getRegistrationDetailsByEmail(detail.getEmail());
		for(RegistrationDetails ele: saved) {
			if(detail.getOtp() == ele.getOtp()) {
				ele.setFirstname(detail.getFirstname());
				ele.setLastname(detail.getLastname());
				ele.setPassword(detail.getPassword());
				ele.setRole("user");
				service.saveRegistrationDetails(ele);
				return "redirect:/registrationStatus";
			}
			
		}
		
//		service.deleteRegistrationDetail(detail.getEmail());
		model.addAttribute("otpMismatch", "Otp is not correct");
		return "userLogin";

	}
	
	@PostMapping("/sendOTP/{email}")
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public void sendOtp(@PathVariable("email") String email, Model model) {
		int status = userService.sendOtp(email);
		if (status ==1) {
			model.addAttribute("message", "User aleady existing");
		}
		System.out.println("request mapped " + email);
		
	}
	
	@GetMapping("/getRegistrationDetails") //1
	public String getDetails(Model model) {
		List<RegistrationDetails> users = service.getRegistrationDetails();
		model.addAttribute("users", users);
//		List<RegistrationDetails> saved = service.getRegistrationDetailsByEmail("bodeddularajasekharreddy2002@gmail.com");
//    	for(RegistrationDetails detail:saved) {
//    		 System.out.println("Blood Group: " + detail.getBloodGroup());
//    		model.addAttribute("userData", detail);
//    	}
		return "details";
	}
	
	@PostMapping("/resetPassword")
//	public String resetPassword(@PathVariable("email") String email,@PathVariable("otp") int otp,@PathVariable("password") String password, Model model) {
	public String resetPassword(@ModelAttribute("detail") RegistrationDetails detail, Model model) {
		
		int status = userService.resetPassword(detail.getEmail(), detail.getOtp(),detail.getPassword(), model);
		if (status==1) 
			return "redirect:/userLogin";
		return "foregetPassword";
	}
	
	@GetMapping("/getRegistrationDetailsById/{id}") //1
	public Optional<RegistrationDetails> findDetailsById(@PathVariable("id") int id) {
		return service.getRegistrationDetailsById(id);
	}
	
	@GetMapping("/getRegistrationDetailsByEmail/{email}") //1
	public List<RegistrationDetails> findDetailsByEmail(@PathVariable("email") String email) {
		return service.getRegistrationDetailsByEmail(email);
	}
	
	@GetMapping("/getRegistrationDetailsByRole/{role}")//1
	public List<RegistrationDetails> findByLoginType(@PathVariable("role") String role) {
		return service.getRegistrationDetailsByRole(role);
	}
	
	
}
