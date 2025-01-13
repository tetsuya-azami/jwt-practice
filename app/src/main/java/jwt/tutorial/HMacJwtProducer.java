package jwt.tutorial;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.time.OffsetDateTime;
import java.util.UUID;

public class HMacJwtProducer {
    private String secretKey;

    public HMacJwtProducer(String key) {
        this.secretKey = key;
    }

    public String generateToken() {
        Algorithm alg = Algorithm.HMAC256(secretKey);

        return JWT.create()
                .withIssuer("HmacJwtProducer")
                .withSubject("ID12345")
                .withExpiresAt(OffsetDateTime.now().plusHours(1).toInstant())
                .withIssuedAt(OffsetDateTime.now().toInstant())
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("email", "hoge@example.com")
                .withArrayClaim("groups", new String[]{"member", "admin"})
                .sign(alg);
    }
}
