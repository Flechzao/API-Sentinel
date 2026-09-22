package com.demo.vulnapp.model;

public class ProfileUpdateDto {

    private String name;
    private String email;

    public ProfileUpdateDto() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}
