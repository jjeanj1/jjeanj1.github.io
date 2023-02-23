---
title: AWS Lambda Authorizer with OKTA
author: jjeanj1
date: 2023-02-22 11:10:00 +0800
categories: [Blogging]
tags: [aws, java lambda authorizer, aws api gateway]
render_with_liquid: false
---

A very common pattern with protecting API services running behind an AWS API Gateway is to use the concept of a Lambda Authorizer. 

## What is a Lambda Authorizer?

A Lambda authorizer (formerly known as a custom authorizer) is an API Gateway feature that uses a Lambda function to control access to your API. Lambda Authorizers can be used to validate incoming request against multiple different services to ensure that the request has the permission to access the service.

Throughout this post, we will cover the process to setup a Lambda function to protect access to a back-end service that is hosted behind an AWS API gateway using a token obtained from an external Authorization Server (OKTA).

## The Why

Many organizations are in the process of going through their Digital Transformation journey and transforming applications to adopt to more modern Architecture patterns, often require a decentralized set of services providing different business functions. A very common pattern to deploy these services is to put them behind an API Gateway and expose these services for consumption based on certain access rules and authorizations. For example, one might have an application that needs to consume a set of micro-services to provide an holistic business function.

## Use Case

Let's say you have a parking garage application that allows a user to login to their account and check if they have any outstanding payments. The application has the following basic requirements

1. Authenticate a User
2. Call an API to check the user's account number (/api/account)
3. Call an API with the account number to check the balance on the account (/api/balance)
4. Return the response back to the user

> Note: Each of these operations require Authentication and Authorization and the user context and account information is also needed. 
{: .prompt-tip }

## Lambda Authorizer to the rescue!

Using a lambda authorizer we can attach a set of policy enforcement


![Desktop View](/Lamda-Authorizer-OKTA1.jpg){: w="700" h="400" }

Here is an example Lambda function, that could be associated with the /api/account and /api/balance endpoint. The function will check a given Bearer JWT and validate the bearer based on the following criteria:

1. Is the bearer expired
2. Validate if the Bearer was signed with the appropriate private key by using the public key pair
3. Is the bearer coming from the correct issuer

If everything evaluates to true, the user ID will be retrieved and allowed access to the back-end services

```java
package com.bitgrep.security.idaas.customauthorizer;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class IdaasExternalAuthorizer2 implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final Logger LOG = Logger.getLogger(IdaasExternalAuthorizer2.class.getName());

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        
        String issuerURI = System.getenv("issuerURI");
        String pubKey = System.getenv("pubKey");
        //**authorizationToken header is required if using authorizer
        String authheader = (String) event.get("authorizationToken");
        String Auth=null;
        String principalId=null;
        String resource = (String) event.get("methodArn");
        LOG.info("resource value --->" + resource);
        LOG.info("authheader value --->" + authheader);
        
        //evaluating if the incoming event hashmap is not empty
        if (!authheader.isEmpty()){
          //if(auth)
            System.out.println("**********" + authheader);
            String validateTokenResponse = ValidateJWT(authheader, issuerURI, pubKey);
            if(validateTokenResponse != null) {
                Auth="allow";
                principalId = validateTokenResponse;
            }else {
                Auth="unauthorized";
            }
        }else {
            Auth="deny";
        }
        
        switch (Auth) {
             case "allow":
                return generatePolicy(principalId, "Allow", resource);
            case "deny":
                return generatePolicy(principalId, "Deny", resource);
            case "unauthorized":
                throw new RuntimeException("Unauthorized");
            default:
                throw new RuntimeException("fail");
        }
    }

    private Map<String, Object> generatePolicy(String principalId, String effect, String resource) {
        Map<String, Object> authResponse = new HashMap<>();
        authResponse.put("principalId", principalId);
        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17"); // default version
        Map<String, String> statementOne = new HashMap<>();
        statementOne.put("Action", "execute-api:Invoke"); // default action
        statementOne.put("Effect", effect);
        statementOne.put("Resource", resource);
        policyDocument.put("Statement", new Object[] {statementOne});
        authResponse.put("policyDocument", policyDocument);
        if ("Allow".equals(effect)) {
            LOG.info("*********" + effect); 
            Map<String, Object> context = new HashMap<>();
            context.put("key", "value");
            context.put("numKey", Long.valueOf(1L));
            context.put("boolKey", Boolean.TRUE);
            authResponse.put("context", context);
        }
        return authResponse;
    }

    public static String ValidateJWT(String authheader, String issuerURI, String pubKey) {

        String email=null;
    
        RSAPublicKey rsapublicKey = getRSAPublicKey(Base64.getDecoder().decode(pubKey));
        Algorithm algorithmRSA = Algorithm.RSA512(rsapublicKey, null);

        
        JWTVerifier verifier = JWT.require(algorithmRSA).withIssuer(issuerURI).build();

        try {
              DecodedJWT jwt = verifier.verify(authheader);
              
              //Validate if the token is not expired
              String created_time = jwt.getClaim("created_time").asString();
              ZonedDateTime time = ZonedDateTime.of(LocalDateTime.parse(created_time),ZoneOffset.UTC);
              int expiryDuration = 4;
              ZonedDateTime expiryTime = time.plusHours(expiryDuration);

              boolean isExpiryReached = ZonedDateTime.now().isBefore(expiryTime);
              
              if (isExpiryReached) {
                  LOG.info("JWT not expired ");
                  email = jwt.getClaim("email").asString();
                  String issuer = jwt.getIssuer();
                  LOG.info("email..." + email + "issuer..." + issuer);
                  
               } else {
                   LOG.info("JWT expired");
               }
              
        } catch (TokenExpiredException exception) {
                System.out.println("Message: Expired token");
        } catch (JWTVerificationException exception) {
                System.out.println("Message: Invalid signature");
        } 
        return email;
    }

    
    private static RSAPublicKey getRSAPublicKey(byte[] keyBytes) {
        RSAPublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = (RSAPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }
        return publicKey;
    }

    //extract token value from authorization header in format bearer:token
    public static String Extract(String authheader) {
        String token = null;
        final String[] clientCredentials = authheader.split(":", 2);
        if (clientCredentials.length == 2) {
            token = clientCredentials[1].trim();
            LOG.info("Extracted Token..." + token);       
            return token;
        }else {
            return "Invalid Token";
        }
    }    
}
```