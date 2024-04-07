import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class JWTTokenVerifierTest {
    @Test
    void shouldGenerateJWTToken() throws JOSEException {
        /**
         * issuer: https:test.com
         * audience : test-aud
         * role: admin
         */
        String secretKey = "12345678909876543212345678909876";
        String token = null;
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("https:test.com")
                .audience("test-aud").expirationTime(new Date(new Date().getTime() + 10000))
                .claim("role", "admin");
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
        signedJWT.sign(new MACSigner(secretKey));
        token = signedJWT.serialize();
        assertTrue(new JWTTokenVerifier().verifyTokenWithSecret(token, secretKey));
    }

    @Test
    void shouldVerifyJWTTokenWIthPublicKey() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).generate();

        String token = null;
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("https:test.com")
                .audience("test-aud").expirationTime(new Date(new Date().getTime() + 10000))
                .claim("role", "admin");
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
        signedJWT.sign(new RSASSASigner(key));
        token = signedJWT.serialize();
        assertTrue(new JWTTokenVerifier().verifyTokenWithPublicKey(token, key.toPublicKey()));


    }
}
