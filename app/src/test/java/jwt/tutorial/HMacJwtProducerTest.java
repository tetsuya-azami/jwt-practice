package jwt.tutorial;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HMacJwtProducerTest {
    private static final OffsetDateTime NOW = OffsetDateTime.of(LocalDate.of(2000, 1, 2), LocalTime.of(3, 4, 5), ZoneOffset.of("+09:00"));
    private static final UUID UUID = java.util.UUID.fromString("42550138-1fd5-4dde-b799-ea20134f733f");
    private static final MockedStatic<OffsetDateTime> mockedOffsetDateTime = Mockito.mockStatic(OffsetDateTime.class);
    private static final MockedStatic<UUID> mockedUUIDProvider = Mockito.mockStatic(UUID.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Base64.Decoder urlDecoder = Base64.getUrlDecoder();

    @BeforeAll
    static void setUp() {
        mockedOffsetDateTime.when(OffsetDateTime::now).thenReturn(NOW);
        mockedUUIDProvider.when(java.util.UUID::randomUUID).thenReturn(UUID);
    }

    @Test
    void test() throws JsonProcessingException {
        HMacJwtProducer hmacJwtProducer = new HMacJwtProducer("dummy-secret");
        String token = hmacJwtProducer.generateToken();

        String[] split = token.split("\\.");
        String actualHeader = split[0];
        String actualPayload = split[1];
        //  TODO:
        //  String actualSignature = split[2];

        String expectedHeader = """
                {
                  "alg": "HS256",
                  "typ": "JWT"
                }
                """;

        String expectedPayload = """
                {
                  "iss": "HmacJwtProducer",
                  "sub": "ID12345",
                  "iat": %%iat%%,
                  "exp": %%exp%%,
                  "jti": "42550138-1fd5-4dde-b799-ea20134f733f",
                  "email": "hoge@example.com",
                  "groups": [
                    "member",
                    "admin"
                  ]
                }
                """.replaceFirst("%%exp%%", String.valueOf(NOW.plusHours(1).toInstant().getEpochSecond()))
                .replaceFirst("%%iat%%", String.valueOf(NOW.toInstant().getEpochSecond()));

        // headerが予期した値であること
        String decodedActualHeader = new String(urlDecoder.decode(actualHeader));
        assertEquals(
                objectMapper.readTree(expectedHeader),
                objectMapper.readTree(decodedActualHeader)
        );

        // payloadが予期した値であること
        String decodedActualPayload = new String(urlDecoder.decode(actualPayload));
        assertEquals(
                objectMapper.readTree(expectedPayload),
                objectMapper.readTree(decodedActualPayload)
        );

        // TODO: signatureが予期した値であること
    }
}
