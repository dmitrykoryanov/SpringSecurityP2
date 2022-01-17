package rc.bootsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rc.bootsecurity.dao.UserRepository;
import rc.bootsecurity.model.User;

import java.util.List;

@RestController
@RequestMapping("api/public")
@CrossOrigin
public class PublicRestApiController {

    private UserRepository userRepository;

    public PublicRestApiController(){}

    @Autowired
    public PublicRestApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //available to all authenticated users
    @GetMapping("/test")
    public String test1(){
        return "API Test 1";
    }

    //for managers
    @GetMapping("/management/reports")
    public String reports(){
        return "Some report data";
    }

    //for admins only
    @GetMapping("/admin/users")
    public List<User> getUsers(){
        return this.userRepository.findAll();
    }

}
