package hello.springoauth2clientjwt.dto;

import lombok.Data;

@Data
public class UserDTO {

    private String role;
    private String name;
    private String username;
}