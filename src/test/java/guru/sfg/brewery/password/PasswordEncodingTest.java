package guru.sfg.brewery.password;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordEncodingTest {

    static final String PASSWORD = "PASSWORD";

    // Considered slow for brute force attacks. Default strength value is 10. If stronger - length of encoded string is longer.
    @Test
    void bcryptPasswordEncoder() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode(PASSWORD));
    }

    @Test
    void testSHA256() {
        PasswordEncoder passwordEncoder = new StandardPasswordEncoder();

        // Uses random salt so the result will always be the same.
        System.out.println(passwordEncoder.encode(PASSWORD));
        System.out.println(passwordEncoder.encode(PASSWORD));

    }

    // LdapPasswordEncoder uses random salt. Different output always.
    @Test
    void testLdap() {
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        System.out.println(ldap.encode(PASSWORD));
        System.out.println(ldap.encode(PASSWORD));

        String encodedPwd = ldap.encode(PASSWORD);
        // Spring Security uses this matches() method to compare given password and the saved password.
        assertTrue(ldap.matches(PASSWORD, encodedPwd));
    }

    // MD5 hashing example
    @Test
    void hashingExample() {

        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));

        String salted = PASSWORD + "ThisIsMySaltValue";
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
    }

    // NoOp password encoder
    @Test
    void testNoOperationsPasswordEncoder() {

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
        PasswordEncoder noOpPasswordEncoder = NoOpPasswordEncoder.getInstance();
        System.out.println(noOpPasswordEncoder.encode(PASSWORD));
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.ofHours(3));
        System.out.println(formatter.format(now.plusSeconds(3600)));
    }
}
