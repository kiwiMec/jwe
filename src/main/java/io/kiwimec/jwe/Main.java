package io.kiwimec.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jwt.*;

public class Main {
  public static void main(String[] args) throws Exception {

    // create our agents
    Agent alice = new Agent();
    Agent bob = new Agent();

    // get them to exchange public keys with each other
    alice.sharePubKeysWith(bob);
    bob.sharePubKeysWith(alice);

    // create a claim set for alice to send to Bob
    JWTClaimsSet claimsSetToSend = new JWTClaimsSet.Builder()
        .subject("alice")
        .issuer("https://kiwimec.io")
        .build();

    // get alice to send the claims to bob in a JWE to print
    String serialisedJwe = alice.createAJweFrom(claimsSetToSend);
    JWTClaimsSet claimsSetReturned = bob.extractClaimsFrom(serialisedJwe);

    // if claimsSetReturned is not null verify its contents
    if(null != claimsSetReturned) {
      System.out.println("claimsSetToSend.subject: " + claimsSetToSend.getSubject());
      System.out.println("claimsSetReturned.subject: " + claimsSetReturned.getSubject());
    }

    System.out.println("Hello World!");
  }
}