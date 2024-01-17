package com.example.demo.repository;



import java.util.*;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.demo.entity.Inventory;


@Repository
public interface InventoryRepository extends JpaRepository<Inventory, Integer> {
	
	//public List<Inventory> findByBloodGroup(String BloodGroup);
	 public List<Inventory> findByBloodGroup(String bloodGroup);
	 
	// @Query("SELECT bloodGroup, SUM(quantity) FROM Inventory GROUP BY bloodGroup")
	 //@Query("SELECT i.bloodGroup, SUM(i.quantity) FROM Inventory i GROUP BY i.bloodGroup")
	   //public List<Object[]> findQuantityByBloodGroup();
//	 @Query(value = "SELECT blood_group, SUM(quantity) FROM blood_inventory GROUP BY blood_group", nativeQuery = true)
//	    List<Inventory> findQuantityByBloodGroup();
	 @Query("SELECT bloodGroup, COUNT(bloodId) FROM Inventory GROUP BY bloodGroup")
	 
	    public Map<String, Long> getCountByBloodGroup();
	
	 
	//public List<Object[]> findDistinctBloodGroupAndSumQuantityBy();
	   
	   
	   
//	   @Transactional
//		@Modifying
//		@Query(value = "delete from Inventory where BloodId = ?1",nativeQuery = true)
//		public void deleteByBloodId(Integer BloodId);
	   public void deleteByBloodId(int bloodId);
	   
	   
	   
	   
	}
	   
	


