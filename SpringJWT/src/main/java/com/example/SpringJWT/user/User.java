package com.example.SpringJWT.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Data// get and setter plus constructor aus Lombok
@Builder
@NoArgsConstructor
@AllArgsConstructor

@Entity// To create the Table user in our Database
@Table(name="_user")
public class User implements UserDetails {
    @Id
    @GeneratedValue// make the id autoincremented
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;// has the role of username

    private String password;
    @Enumerated(EnumType.STRING)// to specify that the type of enum we have is String not Ordinal(for numbers)
    private Role role;


    @Override
    // should return a list of Role
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return email;// our username for the login is the Email Adress
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;// to enable the connection
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    @Override
    public String getPassword() {
        return password;
    }
}
