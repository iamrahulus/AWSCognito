package com.amazonaws.cognito.samples;

public abstract class JWTTokenValidator {

	public static String COGNITO = "Cognito";
	
	String validationSource;
	
	String issuer;	
	
	public abstract boolean validateToken(String token, String keyId);
	
	public static CognitoJWTTokenValidator getCognitoJWTValidator(String userPool, String region){
		return new CognitoJWTTokenValidator(userPool, region);
	}

}
