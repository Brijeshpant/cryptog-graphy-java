import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.*;
import java.util.logging.Logger;

public class JWTTokenVerifier {
    public boolean verifyTokenWithSecret(String token, String secretKey) throws KeyLengthException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("https:test.com");
        JWTClaimsSet claimsSet;
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new SingleKeyJWSKeySelector<>(JWSAlgorithm.HS256,  new MACSigner(secretKey).getSecretKey()));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>( new HashSet<>(List.of("test-aud","test-aud2")),builder.build(), new HashSet<>(List.of("role", JWTClaimNames.AUDIENCE, JWTClaimNames.ISSUER, JWTClaimNames.EXPIRATION_TIME)), null));

        try {
             claimsSet = processor.process(token, null);
        } catch (ParseException |BadJOSEException | JOSEException e) {
            System.out.printf("Validation failure : %s", e.getMessage());
          return false;
        }
        return true;
    }

    public boolean verifyTokenWithPublicKey(String token, PublicKey publicKey) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("https:test.com");
        JWTClaimsSet claimsSet;
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();


        processor.setJWSKeySelector((header, context) -> Collections.singletonList(publicKey));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>( new HashSet<>(List.of("test-aud","test-aud2")),builder.build(), new HashSet<>(List.of("role", JWTClaimNames.AUDIENCE, JWTClaimNames.ISSUER, JWTClaimNames.EXPIRATION_TIME)), null));

        try {
            claimsSet = processor.process(token, null);
        } catch (ParseException |BadJOSEException | JOSEException e) {
            System.out.printf("Validation failure : %s", e.getMessage());
            return false;
        }
        return true;

    }
}
