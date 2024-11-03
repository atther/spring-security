package com.ather.spring.security.login.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ather.spring.security.login.models.User;
import com.ather.spring.security.login.repository.UserRepository;

/*UserDetailsServiceImpl class, which implements the UserDetailsService interface
 in a Spring Boot application. This class is responsible for loading user details
 and creating a UserDetails object for authentication purposes.*/
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  @Autowired
  UserRepository userRepository;

  /*
  * The loadUserByUsername method is an implementation of the loadUserByUsername method
  * defined in the UserDetailsService interface. This method is called by Spring Security
  * when it needs to retrieve user details for authentication.
  *
  * When a user attempts to log in, they provide a username (or other unique identifier).
  * The loadUserByUsername method is responsible for looking up the user in the user
  * repository based on this provided username.
  *
  * If the user is not found in the database, the method logs an error and throws a UsernameNotFoundException.
  * This exception is a standard exception in Spring Security and indicates that the requested user was not found.
  * If the user is found, the method logs a successful authentication message and
  * creates a CustomUserDetails(UserDetailsImpl) object.
  *
  *
  * CustomUserDetails(UserDetailsImpl)  is typically a custom implementation of the
  * UserDetails interface that wraps the user information, such as username and password,
  *  as well as user roles and authorities. The UserDetails object
  *  (in this case, CustomUserDetails(UserDetailsImpl) ) is returned by the method.
  * This object is used by Spring Security for authentication and authorization checks
  * */

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }

}
