package com.amazonaws.cognito.samples;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.cognitoidp.AbstractAWSCognitoIdentityProvider;

public class MyAuthenticationProvider extends AbstractAWSCognitoIdentityProvider implements AWSCredentialsProvider{

	@Override
	public AWSCredentials getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void refresh() {
		// TODO Auto-generated method stub
		
	}
	
	
	
}
