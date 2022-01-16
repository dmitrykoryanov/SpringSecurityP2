package rc.bootsecurity.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@NoArgsConstructor
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private int active;

    private String roles = "";

    private String permissions = "";

    public User(String username, String password, String roles, String permissions){
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.permissions = permissions;
        this.active = 1;
    }

    public List<String> getRoleList(){

        if(this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }

        return new ArrayList<>();
    }

    public List<String> getPermissionList(){

        if(this.permissions.length() > 0){
            return Arrays.asList(this.permissions.split(","));
        }

        return new ArrayList<>();
    }
}
