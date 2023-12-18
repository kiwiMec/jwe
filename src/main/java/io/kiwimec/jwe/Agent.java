package io.kiwimec.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

class Agent {

    // name of this agent
    private String agentName;

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

    public Agent(String name) throws Exception {

        // remember our name
        agentName = name;

        // set up signing keys
        keyCounter++;
        priSig = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        pubSig = priSig.toPublicJWK();
        System.out.println(agentName + "'s private signing key:\n" + priSig);
        System.out.println(agentName + "'s public signing key:\n" + pubSig);

        // set up encryption keys
        keyCounter++;
        priEnc = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.ENCRYPTION)
                .generate();
        pubEnc = priEnc.toPublicJWK();
        System.out.println(agentName + "'s private encryption key:\n" + priEnc);
        System.out.println(agentName + "'s public encryption key:\n" + pubEnc);
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
        // -----
        // If you want to use a hardware based keystore or particular secure 
        // random number generator you will need to initilise them somewhere
        // and then reference them as per below. Note that the euqivalent will
        // need to be done in the receiving code.
        // See also https://connect2id.com/products/nimbus-jose-jwt/examples/pkcs11
        //
        //RSASSASigner signer = new RSASSASigner(priSig);
        //signer.getJCAContext().setProvider(/* Reference your JCA provider here. */);
        //signer.getJCAContext().setSecureRandom(/* Reference your secure random number generator here. */);
        //signedJWT.sign(signer); /* Uncomment this line of code and comment out the next. */
        // -----
        signedJWT.sign(new RSASSASigner(priSig));
        System.out.println(agentName + " signed JWT with header:\n" + signedJWT.getHeader());
        System.out.println(agentName + " signed JWT with claims:\n" + signedJWT.getJWTClaimsSet());
        System.out.println(agentName + " signed JWT with signature:\n" + signedJWT.getSignature());

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // indicate that the payload is a JWT
                        .build(),
                new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(contactPubEnc));
        System.out.println(agentName + " created a JWE with header:\n" + jweObject.getHeader());
        System.out.println(agentName + " created a JWE with encrypted key:\n" + jweObject.getEncryptedKey());
        System.out.println(agentName + " created a JWE with initialisation vector:\n" + jweObject.getIV());
        System.out.println(agentName + " created a JWE with cypher text:\n" + jweObject.getCipherText());
        System.out.println(agentName + " created a JWE with authentication tag:\n" + jweObject.getAuthTag());

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