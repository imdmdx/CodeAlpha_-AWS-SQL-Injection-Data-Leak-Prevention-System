# AWS SQL Injection & Data Leak Prevention System

## Project Overview

This project is a cloud-based web application designed to demonstrate
multiple security mechanisms for protecting user data from SQL injection
and unauthorized access.

The application is built using Python Flask and is designed to run on
Amazon EC2 with Amazon RDS MySQL as the database.

---

## Objectives

- Prevent SQL injection attacks.
- Protect user passwords using Argon2 password hashing.
- Encrypt selected sensitive information using AES-256-GCM.
- Implement capability-based authorization.
- Restrict database access through AWS security groups.
- Provide rate limiting and CSRF protection.
- Monitor security-related application events.
- Make the application accessible through a web browser.

---

## Technology Stack

### Cloud

- Amazon EC2
- Amazon RDS MySQL
- Amazon VPC
- AWS IAM
- Amazon CloudWatch

### Programming

- Python
- Flask
- SQLAlchemy
- HTML
- CSS
- JavaScript

### Security

- Parameterized SQL queries
- Argon2 password hashing
- AES-256-GCM
- CSRF protection
- Rate limiting
- Capability-based authorization
- AWS Security Groups

---

## Project Architecture

```text
Internet
   |
   | HTTPS
   v
EC2 Flask Application
   |
   | MySQL TCP 3306
   | Allowed only from EC2 Security Group
   v
RDS MySQL
