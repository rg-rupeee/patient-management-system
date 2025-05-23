package com.rupesh.patient_service.mapper;

import com.rupesh.patient_service.dto.PatientResponseDTO;
import com.rupesh.patient_service.model.Patient;

public class PatientMapper {
	public static PatientResponseDTO toDTO(Patient patient){
		PatientResponseDTO patientDTO = new PatientResponseDTO();
		patientDTO.setId(patient.getId().toString());
		patientDTO.setName(patient.getName());
		patientDTO.setAddress(patient.getAddress());
		patientDTO.setEmail(patient.getEmail());
		patientDTO.setDateOfBirth(patient.getDateOfBirth().toString());
		return patientDTO;
	}
}
