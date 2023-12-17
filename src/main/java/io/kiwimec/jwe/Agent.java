package io.kiwimec.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

class Agent {

    // key pair used to sign/verify the JWT signature
    private RSAKey priSig;
    public RSAKey pubSig;

    // key pair used to en/decrypt the content encryption key
    private RSAKey priEnc;
    public RSAKey pubEnc;

    // public keys of the other agent we are exchanging encrypted data with
    private RSAKey contactPubSig;
    private RSAKey contactPubEnc;

    // static key counter, NOT THREAD SAFE
    static private int keyCounter = 0;

    public Agent() throws Exception {

        // set up signing keys
        keyCounter++;
        priSig = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        pubSig = priSig.toPublicJWK();
        System.out.println("Private signing key:");
        System.out.println(priSig);
        System.out.println("Public signing key:");
        System.out.println(pubSig);

        // set up encryption keys
        keyCounter++;
        priEnc = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.ENCRYPTION)
                .generate();
        pubEnc = priEnc.toPublicJWK();
        System.out.println("Private encryption key:");
        System.out.println(priEnc);
        System.out.println("Public encryption key:");
        System.out.println(pubEnc);
    }

    public void sharePubKeysWith(Agent agent) {
        contactPubSig = agent.pubSig;
        contactPubEnc = agent.priEnc;
    }

    public String createAJweFrom(JWTClaimsSet claimsSet) throws Exception {

        // create a signed JWT, also known as a JWS
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(priSig.getKeyID()).build(),
                claimsSet);
        signedJWT.sign(new RSASSASigner(priSig));
        System.out.println("Signed JWT header:\n" + signedJWT.getHeader());
        System.out.println("Signed JWT claims:\n" + signedJWT.getJWTClaimsSet());
        System.out.println("Signed JWT signature:\n" + signedJWT.getSignature());

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // indicate that the payload is a JWT
                        .build(),
                new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(contactPubEnc));
        System.out.println("JWE header:\n" + jweObject.getHeader());

        return jweObject.serialize();
    }

    public JWTClaimsSet extractClaimsFrom(String jweString) throws Exception {

        // parse the JWE string into a object and decrypt it
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(new RSADecrypter(priEnc));

        // extract the claims and check what we got
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        if(null == signedJWT) {
            System.out.println("Unable to extract a valid JWT.");
            return null;
        }
        if(false == signedJWT.verify(new RSASSAVerifier(contactPubSig))) {
            System.out.println("Extracted JWT failed signature verification.");
            return null;
        }

        return signedJWT.getJWTClaimsSet();
    }
}