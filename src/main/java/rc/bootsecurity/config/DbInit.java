package rc.bootsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rc.bootsecurity.dao.UserRepository;
import rc.bootsecurity.model.User;

import java.util.Arrays;
import java.util.List;

@Service
public class DbInit implements CommandLineRunner {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    //@Autowired
    public DbInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {

        User dmitry = new User("dmitry","koryanov","USER","");
        User admin = new User("admin",passwordEncoder.encode("admin"),"ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager",passwordEncoder.encode("manager"),"MANAGER","ACCESS_TEST1");

        List<User> users = Arrays.asList(dmitry,admin,manager);

        this.userRepository.saveAll(users);
    }
}
