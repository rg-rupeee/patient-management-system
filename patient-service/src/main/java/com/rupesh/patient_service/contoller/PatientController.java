package com.rupesh.patient_service.contoller;

import com.rupesh.patient_service.dto.PatientResponseDTO;
import com.rupesh.patient_service.service.PatientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/patients")
public class PatientController {
	private final PatientService patientService;

	public PatientController(PatientService patientService) {
		this.patientService = patientService;
	}

	@GetMapping
	public ResponseEntity<List<PatientResponseDTO>> getPatients(){
		List<PatientResponseDTO> patients = patientService.getPatients();
		return ResponseEntity.ok().body(patients);
	}
}
