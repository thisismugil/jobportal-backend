package com.example.jobportal.controller;

import com.example.jobportal.entity.Job;
import com.example.jobportal.service.JobService;
import com.example.jobportal.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/jobs")
public class JobController {
    @Autowired
    private JobService jobService;
    @Autowired
    private UserService userService;

    @PostMapping("/add")
    public ResponseEntity<Job> addJob(@RequestBody Job job) {
        // Assume userId from JWT in header; for now, pass in body
        return ResponseEntity.ok(jobService.addJob(job));
    }

    @GetMapping("/all")
    public ResponseEntity<List<Job>> getAllJobs() {
        return ResponseEntity.ok(jobService.getAllJobs());
    }

    @PostMapping("/apply/{jobId}")
    public ResponseEntity<String> applyJob(@PathVariable Long jobId, @RequestParam Long userId) {
        userService.applyJob(userId, jobId);
        return ResponseEntity.ok("Applied");
    }
}