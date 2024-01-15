---
layout: post
title: DevSecOps - Introduction
date: 2024-01-15 15:55 +0000
categories:
- Information
- DevSecOps
tags:
- DevSecOps
img_path: "/assets/img/devsecops"

---
## DevSecOps

![](image_1.png)

### Devops Work

- CI/ CD – In the previous task, we mentioned CI/CD (Continuous Integration and Continuous Deployment); CI/CD deals with the frequent merging of code and adding testing in an automated manner to perform checks as new code is pushed and merged. We can test code as we push and merge thanks to a new dynamic and routine in deployment, which takes the form of minor code changes systematically and routinely. Thanks to this change in dynamic, CI/CD helps detect bugs early and decreases the effort of maintaining modular code massively, which introduces reliable rollbacks of versions/code.
- INFRASTRUCTURE AS CODE (IaC) – a way to manage and provision infrastructure through code and automation. Thanks to this approach, we can reuse code used to deploy infrastructure (for example, cloud instances), which helps inconsistent resource creation and management. Standard tools for IaC are terraform, vagrant, etc. We will use these tools further in the pathway as we experiment with IaC security.
- CONFIGURATION MANAGEMENT – This is where the state of infrastructure is managed constantly and applying changes efficiently, making it more maintainable. Thanks to this, lots of time is saved, and more visibility into how infrastructure is configured. You can use IaC for configuration management.
- ORCHESTRATION – Orchestration is the automation of workflows. It helps achieve stability; for example, by automating the planning of resources, we can have fast responses whenever there is a problem (e.g., health checks failing); this can be achieved thanks to monitoring.
- MONITORING – focuses on collecting data about the performance and stability of services and infrastructure. This enables faster recovery, helps with cross-team visibility, provides more data to analyze for better root-cause analysis, and also generates an automated response, as mentioned earlier.
- MICROSERVICES – An architecture that breaks an application into many small services. This has several benefits, like flexibility if there is a need to scale, reduced complexity, and more options for choosing technology across microservices. We will look at these in more detail in the DevSecOps pathway.

### Shifting left

**Shifting left** is a term used to describe the security methods used in the early stages of development by the devops teams.
In the past the security was handled in the last stages causing sometimes economic issues, however with the automation that we have today we can now analyze the security automatically once a minor change is made to the code.

### DevSecOps Challenges

Prevent security Silos: Security Silos are situations where the security processes are only given to a specific team and nobody is responsible for the security of a solution besides that team. Instead, the DevSecOps team should promote secure solutions and decisions, sharing the responsibilities across all team members instead of having a specialized security engineer.

Lack of Visibility & Prioritization: Security should be treated as a regular aspect an application. Trust should be built between teams, and security should promote the autonomy of teams by establishing processes that instil security.

Stringent Processes: Every new experiment or piece of software must not go through a complicated process and verification against security compliances before being used by developers. Procedures should be flexible to account for these scenarios, where lower-level tasks should be treated differently, and higher-risk tasks and changes are targeted for these more stringent processes. Developers need environments to test new software without common security limitations. These environments are known as "SandBox". 

### DevSecOps Culture

Promote Autonomy of teams: The only way to not leave security behind is by promoting the autonomy of teams. This can be done by automatization of security processes. Security should act as a supporting function that focuses on building trust and creating as much overlap in knowledge between teams as possible.

Visibility and Transparency: For every tool being introduced or practiced, there needs to be a supporting process that provides visibility and promotes transparency to other teams. An example can be create a dashboard with the highest security flaws found accessible to the developers. The developers should have access to the tool to better understand where the flaws came from and why does that tool triggered the flaws. This promotes education and autonomy by extending transparency that, traditionally, was only accessible by security teams.

Account for flexibility thanks to understanding and empathy:  There is a factor that can determine success: the level of understanding and empathy. It is essential to understand how developers/engineers work, what they know to be a risk, and what they prioritize. If you know their perspective, it's easier to build a process that finds common ground and has a higher chance to work vs adding another tool that creates more noise and stress for everyone.

