package com.example.jobportal.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Job {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String description;
    private Long postedBy;  // User ID who posted
}