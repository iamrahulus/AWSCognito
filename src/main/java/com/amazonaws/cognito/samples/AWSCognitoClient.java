package com.amazonaws.cognito.samples;

import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

public class AWSCognitoClient {

	private static AWSCognitoClient client = new AWSCognitoClient();

	private AWSCognitoIdentityProvider providerClient = AWSCognitoIdentityProviderClientBuilder.standard()
			.withRegion("us-east-1").build();

	// AmazonCognitoIdentity providerClient = new AmazonCognitoIdentityClient();

	private String clientId = "5pmv3s344t8u0abn2tgjpkta5u";

	private String userPoolId = "us-east-1_JuHdVEiB5";

	private AWSCognitoClient() {

	}

	public static AWSCognitoClient getClient() {
		return client;
	}

	public AWSCognitoIdentityProvider getAWSCognitoIdProvider() {
		return this.providerClient;
	}

	public String getClientId() {
		return this.clientId;
	}

	public String getUserPoolId() {
		return this.userPoolId;
	}

}
