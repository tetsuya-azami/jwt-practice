package jwt.tutorial;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HMacJwtConsumerTest {
    private static final String secretKey = "dummy-secret";
    private static final OffsetDateTime NOW = OffsetDateTime.now();
    private static final java.util.UUID UUID = java.util.UUID.fromString("42550138-1fd5-4dde-b799-ea20134f733f");
    private static final MockedStatic<OffsetDateTime> mockedOffsetDateTime = Mockito.mockStatic(OffsetDateTime.class);
    private static final MockedStatic<UUID> mockedUUIDProvider = Mockito.mockStatic(UUID.class);

    @BeforeAll
    static void setUp() {
        mockedOffsetDateTime.when(OffsetDateTime::now).thenReturn(NOW);
        mockedUUIDProvider.when(java.util.UUID::randomUUID).thenReturn(UUID);
    }

    @Test
    void test() {
        HMacJwtProducer hMacJwtProducer = new HMacJwtProducer(secretKey);
        String token = hMacJwtProducer.generateToken();

        HMacJwtConsumer hMacJwtConsumer = new HMacJwtConsumer(secretKey);
        DecodedJWT decodedJWT = hMacJwtConsumer.verifyToken(token);

        assert_JWTトークンが正しいこと(decodedJWT);
    }

    private void assert_JWTトークンが正しいこと(DecodedJWT decodedJWT) {
        assertEquals("HS256", decodedJWT.getAlgorithm());
        assertEquals("HMacJwtProducer", decodedJWT.getIssuer());
        assertEquals("ID12345", decodedJWT.getSubject());
        assertEquals(
                NOW.plusHours(1).toInstant().truncatedTo(ChronoUnit.SECONDS),
                decodedJWT.getExpiresAt().toInstant().truncatedTo(ChronoUnit.SECONDS)
        );
        assertEquals(
                NOW.toInstant().truncatedTo(ChronoUnit.SECONDS),
                decodedJWT.getIssuedAt().toInstant().truncatedTo(ChronoUnit.SECONDS)
        );
        assertEquals("hoge@example.com", decodedJWT.getClaim("email").asString());
        assertEquals(List.of("member", "admin"), decodedJWT.getClaim("groups").asList(String.class));
    }
}