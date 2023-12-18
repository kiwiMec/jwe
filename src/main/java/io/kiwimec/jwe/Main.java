package io.kiwimec.jwe;

import com.nimbusds.jwt.*;

public class Main {
  public static void main(String[] args) throws Exception {

    // create our agents
    Agent alice = new Agent("Alice");
    Agent bob = new Agent("Bob");

    // get them to exchange public keys with each other
    alice.sharePubKeysWith(bob);
    bob.sharePubKeysWith(alice);

    // create a claim set for alice to send to Bob
    JWTClaimsSet aliceClaimsSet = new JWTClaimsSet.Builder()
        .subject("alice")
        .issuer("https://alice_and_bob.io")
        .build();

    // get alice to send the claims to bob in a JWE to print
    String serialisedJwe = alice.createAJweFrom(aliceClaimsSet);
    JWTClaimsSet claimsSetExtractedByBob = bob.extractClaimsFrom(serialisedJwe);

    // if claimsSetReturned is not null print its contents so we can visually inspect
    if(null != claimsSetExtractedByBob) {
      System.out.println("Alice's claims set:");
      System.out.println(aliceClaimsSet);
      System.out.println("Claims set extracted by Bob:");
      System.out.println(claimsSetExtractedByBob);
      System.out.println("Serialised JWE:");
      System.out.println(serialisedJwe);
    }

  }
}