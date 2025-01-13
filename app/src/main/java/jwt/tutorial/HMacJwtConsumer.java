package jwt.tutorial;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class HMacJwtConsumer {
    private String secretKey;

    public HMacJwtConsumer(String secretKey) {
        this.secretKey = secretKey;
    }

    public DecodedJWT verifyToken(String token) {
        Algorithm alg = Algorithm.HMAC256(secretKey);
        // TODO: 検証する値の検討()
        JWTVerifier verifier = JWT.require(alg)
                .withIssuer("HMacJwtProducer")
                .build();
        try {
            return verifier.verify(token);
        } catch (TokenExpiredException e) {
            System.out.println("JWT Token has expired");
            throw e;
        } catch (JWTVerificationException e) {
            System.out.println("JWT Verification failed");
            throw e;
        }
    }
}
