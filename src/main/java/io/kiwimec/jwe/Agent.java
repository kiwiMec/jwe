package io.kiwimec.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

class Agent {

    // name of this agent
    private String agentName;

    // time counter for telemetry, NOT THREAD SAFE
    static private long timeMarker = 0;
    static private long timeElapsed = 0;

    // key pair used to sign/verify the JWT signature
    private RSAKey priSig;
    public RSAKey pubSig;

    // key pair used to en/decrypt the content encryption key
    private RSAKey priEnc;
    public RSAKey pubEnc;

    // public keys of the other agent we are exchanging encrypted data with
    private RSAKey contactPubSig;
    private RSAKey contactPubEnc;

    // static key counter used to given keys a unquie number, NOT THREAD SAFE
    static private int keyCounter = 0;

    public Agent(String name) throws Exception {

        // remember our name and set the start time if not already set
        agentName = name;
        log("Agent", "Creating new agent:", agentName);

        // set up signing keys
        keyCounter++;
        priSig = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        pubSig = priSig.toPublicJWK();
        log("Agent", agentName + "'s private signing key:", priSig.toString());
        log("Agent", agentName + "'s public signing key:", pubSig.toString());

        // set up encryption keys
        keyCounter++;
        priEnc = new RSAKeyGenerator(2048)
                .keyID(String.format("%04d", keyCounter))
                .keyUse(KeyUse.ENCRYPTION)
                .generate();
        pubEnc = priEnc.toPublicJWK();
        log("Agent", agentName + "'s private encryption key:", priEnc.toString());
        log("Agent", agentName + "'s public encryption key:", pubEnc.toString());
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
        log("createAJweFrom", agentName + " signed JWT with header:", signedJWT.getHeader().toString());
        log("createAJweFrom", agentName + " signed JWT with claims:", signedJWT.getJWTClaimsSet().toString());
        log("createAJweFrom", agentName + " signed JWT with signature:", signedJWT.getSignature().toString());

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // indicate that the payload is a JWT
                        .build(),
                new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(contactPubEnc));
        log("createAJweFrom", agentName + " created a JWE with header:", jweObject.getHeader().toString());
        log("createAJweFrom", agentName + " created a JWE with encrypted key:", jweObject.getEncryptedKey().toString());
        log("createAJweFrom", agentName + " created a JWE with initialisation vector:", jweObject.getIV().toString());
        log("createAJweFrom", agentName + " created a JWE with cypher text:", jweObject.getCipherText().toString());
        log("createAJweFrom", agentName + " created a JWE with authentication tag:", jweObject.getAuthTag().toString());

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
            log("extractClaimsFrom", "Extracted JWT failed signature verification.", "");
            return null;
        }
        if(false == signedJWT.verify(new RSASSAVerifier(contactPubSig))) {
            log("extractClaimsFrom", "Unable to extract a valid JWT.", "");
            return null;
        }

        return signedJWT.getJWTClaimsSet();
    }

    // Because I don't want to include a full logger or use the system one
    static public void log(String functionName, String summary, String artefact) {

        if(0 == timeMarker) {
            timeMarker = System.currentTimeMillis();
        }

        long current = System.currentTimeMillis();
        long interval = current - timeMarker;
        timeElapsed = timeElapsed + interval;
        timeMarker = current;

        System.out.println("---[ fn: " + functionName + " ][ time: " + current + " ][ interval: " + interval + " ][ elapsed: " + timeElapsed + " ]---");
        System.out.println(summary);
        System.out.println(artefact);
        System.out.println("");
    }
}