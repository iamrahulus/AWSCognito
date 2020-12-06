package com.amazonaws.cognito.samples;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;

public class CognitoUserAuthenticator {

	public static void main(String args[]) throws Exception{
		CognitoUserAuthenticator auth = new CognitoUserAuthenticator();
		auth.authenticate(args[0], args[1]);
	}

	public CognitoUserAuthenticator() {

	}

	public void authenticate(String userName, String password)  throws Exception{

		AWSCognitoIdentityProvider providerClient = AWSCognitoIdentityProviderClientBuilder.standard()
				.withRegion("us-east-1").build();

		AdminInitiateAuthRequest request = new AdminInitiateAuthRequest();
		request.setAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH);
		request.setClientId("4r24f87k4mar4neni6amkd2mk1");
		request.setUserPoolId("us-east-1_BDORsFhsg");
		request.addAuthParametersEntry("USERNAME", userName);
		request.addAuthParametersEntry("PASSWORD", password);

		AdminInitiateAuthResult adminInitiateAuthResult = providerClient.adminInitiateAuth(request);

		
		
		String session = adminInitiateAuthResult.getSession();
		String challenge = adminInitiateAuthResult.getChallengeName();

		while (!adminInitiateAuthResult.getChallengeParameters().isEmpty()) {
			RespondToAuthChallengeRequest respondToAuthChallengeRequest = new RespondToAuthChallengeRequest();
			Map challengeResponses = new HashMap();
			respondToAuthChallengeRequest.setClientId("4r24f87k4mar4neni6amkd2mk1");
			challengeResponses.put("USERNAME", userName);
			respondToAuthChallengeRequest.setSession(session);
			if (challenge.equals("NEW_PASSWORD_REQUIRED")) {
				respondToAuthChallengeRequest.setChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED);
				challengeResponses.put("NEW_PASSWORD", "New@Passw0rd");
				respondToAuthChallengeRequest.setChallengeResponses(challengeResponses);
				RespondToAuthChallengeResult result = providerClient
						.respondToAuthChallenge(respondToAuthChallengeRequest);
			}

		}
		System.out.println("Successfully authenticated!");
		String accessToken = adminInitiateAuthResult.getAuthenticationResult().getAccessToken();
		String refreshToken = adminInitiateAuthResult.getAuthenticationResult().getRefreshToken();
		String tokenType = adminInitiateAuthResult.getAuthenticationResult().getTokenType();
		String idToken = adminInitiateAuthResult.getAuthenticationResult().getIdToken();
		Integer expirationTime = adminInitiateAuthResult.getAuthenticationResult().getExpiresIn();
		UserTokens token = new UserTokens(accessToken, refreshToken, tokenType, idToken, expirationTime);

		FileOutputStream fos = new FileOutputStream("C:/temp/session.ser");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(token);
		oos.flush();
		fos.close();
		oos.close();
		// AmazonCognitoIdentity identity =
		// AmazonCognitoIdentityClientBuilder.defaultClient();

		// AdminGetUserRequest getUserRequest = new AdminGetUserRequest();
		// getUserRequest.setUserPoolId("us-east-1_BDORsFhsg");
		// getUserRequest.setUsername("iamrahulus");
		// System.out.println(idProvider.adminGetUser(getUserRequest));

		// AmazonCognitoIdentity client =
		// AmazonCognitoIdentityClientBuilder.standard().withRegion("us-east-1").build();
		//
		//
		//
		// GetOpenIdTokenForDeveloperIdentityRequest openIdForDevRequest = new
		// GetOpenIdTokenForDeveloperIdentityRequest();
		//
		// openIdForDevRequest.addLoginsEntry("login.redcross.com",
		// "iamrahulus");
		// openIdForDevRequest.setIdentityPoolId("us-east-1:5fbe3d0e-63e9-41c2-aab3-4d96b437964a");
		//
		//
		// GetOpenIdTokenForDeveloperIdentityResult result = client
		// .getOpenIdTokenForDeveloperIdentity(openIdForDevRequest);
		//
		// System.out.println(result.getToken());
		////
		//
		//
		//// GetCredentialsForIdentityRequest credsForIdRequest = new
		// GetCredentialsForIdentityRequest();
		//// credsForIdRequest.addLoginsEntry("cognito-identity.amazonaws.com",
		// result.getToken());
		//// credsForIdRequest.setIdentityId(result.getIdentityId());
		//// GetCredentialsForIdentityResult credsResult =
		// client.getCredentialsForIdentity(credsForIdRequest);
		//
		//// String token = credsResult.getCredentials().getSessionToken();
		//// System.out.println(token);
		//// AWSCognitoIdentityProvider idProvider =
		// AWSCognitoIdentityProviderClient.builder().withRegion("us-east-1")
		//// .build();
		//// GetUserRequest getUserRequest = new GetUserRequest();
		//// getUserRequest.setAccessToken(token);
		//// idProvider.getUser(getUserRequest);
		//

	}

}
