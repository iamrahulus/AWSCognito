package com.amazonaws.cognito.samples;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;
import java.util.SimpleTimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.cognitoidentity.model.GetIdRequest;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;
import com.amazonaws.services.cognitoidentity.model.GetOpenIdTokenForDeveloperIdentityRequest;
import com.amazonaws.services.cognitoidentity.model.GetOpenIdTokenRequest;
import com.amazonaws.services.cognitoidentity.model.GetOpenIdTokenResult;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpRequest;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.PasswordResetRequiredException;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.amazonaws.services.cognitoidp.model.UserNotConfirmedException;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.util.StringUtils;

public class UserSignupProcess {

	public static void main(String args[]) throws Exception {
		UserSignupProcess signUpProcess = new UserSignupProcess();
		signUpProcess.process("iamrahulus", "India@123", "iamrahulus@gmail.com", "1234");
	}

	public void process(String userName, String password, String email, String donorId) throws Exception {

		AWSCognitoClient client = AWSCognitoClient.getClient();
		AWSCognitoIdentityProvider provider = client.getAWSCognitoIdProvider();

		// this.signUp("iamrahulus", "India@123", "iamrahulus@gmail.com",
		// "1234");
		attemptToSignIn(provider, client.getClientId(), client.getUserPoolId(), userName, password, email);
		// adminAuthUser(provider, client.getClientId());
	}

	private void attemptToSignIn(AWSCognitoIdentityProvider provider, String clientId, String userPool, String username,
			String password, String emailId) throws Exception {
		try {

			AuthenticationHelper helper = new AuthenticationHelper("us-east-1_JuHdVEiB5");

			String srpA = helper.getA().toString(16);
			InitiateAuthRequest authRequest = createInitiateAuthRequest(srpA, clientId, username);
			InitiateAuthResult result = provider.initiateAuth(authRequest);
			System.out.println(result);

			String challengeName = result.getChallengeName();

			String salt = result.getChallengeParameters().get("SALT");
			String secret_block = result.getChallengeParameters().get("SECRET_BLOCK");
			String srp_b = result.getChallengeParameters().get("SRP_B");
			String userid = result.getChallengeParameters().get("USER_ID_FOR_SRP");

			if (challengeName.equals("PASSWORD_VERIFIER")) {
				// Build Response to Challenge
				RespondToAuthChallengeRequest authResponse = new RespondToAuthChallengeRequest();
				authResponse.setClientId(clientId);
				authResponse.setChallengeName(ChallengeNameType.PASSWORD_VERIFIER);
				BigInteger B = new BigInteger(srp_b, 16);

				byte[] key = helper.getPasswordAuthenticationKey(username, password, B, new BigInteger(salt, 16));

				String passwordClaimSignature = getPasswordClaimSignature(key,
						Base64.getDecoder().decode(secret_block.getBytes()), username);

				RespondToAuthChallengeResult res = provider.respondToAuthChallenge(
						getRespondToAuthChallengeRequest(clientId, userid, passwordClaimSignature, secret_block));
				System.out.println(res);
				AuthenticationResultType authenticationResultType = res.getAuthenticationResult();
				String accessToken = authenticationResultType.getAccessToken();
				Integer expirationTime = authenticationResultType.getExpiresIn();
				String idToken = authenticationResultType.getIdToken();
				String refreshToken = authenticationResultType.getRefreshToken();
				String tokenType = authenticationResultType.getTokenType();
				// JWTTokenParser.parseToken(accessToken);

				GetIdRequest idRequest = new GetIdRequest();
				idRequest.setIdentityPoolId("us-east-1:2fc6acd9-554f-435e-b7be-8048e8d4bc3e");
				// idRequest.setIdentityPoolId("us-east-1:us-east-1_JuHdVEiB5");
				idRequest.addLoginsEntry("cognito-idp.us-east-1.amazonaws.com/us-east-1_JuHdVEiB5", idToken);
				AmazonCognitoIdentityClient client = new AmazonCognitoIdentityClient();

				GetIdResult idResult = client.getId(idRequest);

				GetOpenIdTokenRequest openIdTokenReq = new GetOpenIdTokenRequest();
				openIdTokenReq.setIdentityId(idResult.getIdentityId());
				openIdTokenReq.addLoginsEntry("cognito-idp.us-east-1.amazonaws.com/us-east-1_JuHdVEiB5", idToken);
				GetOpenIdTokenResult openIdTokenResult = client.getOpenIdToken(openIdTokenReq);

				GetOpenIdTokenForDeveloperIdentityRequest r = new GetOpenIdTokenForDeveloperIdentityRequest();
				r.addLoginsEntry("cognito-idp.us-east-1.amazonaws.com/us-east-1_JuHdVEiB5", idToken);
				// r.setIdentityPoolId("us-east-1:JuHdVEiB5");
				// client.getOpenIdTokenForDeveloperIdentity(r);

				// GetCredentialsForIdentityRequest credsForIdReq = new
				// GetCredentialsForIdentityRequest();
				// credsForIdReq.addLoginsEntry("cognito-idp.us-east-1.amazonaws.com/us-east-1_JuHdVEiB5",
				// idToken);
				// credsForIdReq.setIdentityId(idResult.getIdentityId());
				// GetCredentialsForIdentityResult credsForIdResponse =
				// client.getCredentialsForIdentity(credsForIdReq);
				// System.out.println(credsForIdResponse.getCredentials().getSessionToken());
				System.out.println("TOKEN: " + openIdTokenResult.getToken());

				AssumeRoleWithWebIdentityRequest iamRequest = new AssumeRoleWithWebIdentityRequest();
				iamRequest.setWebIdentityToken(idToken);
				iamRequest.setRoleSessionName("mySession");
				iamRequest.setRoleArn("arn:aws:iam::190732613123:role/Cognito_Federated");
				AWSSecurityTokenService sts = AWSSecurityTokenServiceClient.builder().withRegion("us-east-1").build();
				AssumeRoleWithWebIdentityResult webIdResult = sts.assumeRoleWithWebIdentity(iamRequest);
				System.out.println(webIdResult.getSubjectFromWebIdentityToken());
				System.out.println(webIdResult.getCredentials());
				BasicSessionCredentials basicSessionCredentials = new BasicSessionCredentials(
						webIdResult.getCredentials().getAccessKeyId(),
						webIdResult.getCredentials().getSecretAccessKey(),
						webIdResult.getCredentials().getSessionToken());
				AmazonS3Client s3 = new AmazonS3Client(basicSessionCredentials);

				s3.createBucket("15pmv3s344t8u0abn2tgjpkta5u1");
			}
		} catch (UserNotConfirmedException unce) {

			System.out.println(provider.confirmSignUp(getConfirmSignUpRequest(clientId, username, askForCode())));
		} catch (PasswordResetRequiredException prre) {
			ForgotPasswordResult result = provider.forgotPassword(getForgotPasswordRequest(clientId, username));
			String deliveryMedium = result.getCodeDeliveryDetails().getDeliveryMedium();
			String destination = result.getCodeDeliveryDetails().getDestination();
			System.out.println(deliveryMedium.toLowerCase() + " has been sent to " + destination);
			ConfirmForgotPasswordResult confirmForgotPasswordResult = provider
					.confirmForgotPassword(getConfirmForgotPasswordRequest(clientId, username, askForCode()));
			System.out.println(confirmForgotPasswordResult);
		}
	}

	private String getPasswordClaimSignature(byte[] key, byte[] secretBlock, String username) throws Exception {
		// TODO Auto-generated method stub
		byte[] hmac;
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
			mac.init(keySpec);
			mac.update("JuHdVEiB5".getBytes(StandardCharsets.UTF_8));
			mac.update(username.getBytes(StandardCharsets.UTF_8));
			mac.update(secretBlock);
			Date timestamp = new Date();
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
			simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
			String dateString = simpleDateFormat.format(timestamp);
			byte[] dateBytes = dateString.getBytes(StringUtils.UTF8);
			hmac = mac.doFinal(dateBytes);
		} catch (Exception e) {
			throw e;
		}
		return new String(Base64.getEncoder().encode(hmac), StringUtils.UTF8);
	}

	private String askForCode() {
		System.out.println("Please enter the code: ");
		Scanner userInput = new Scanner(System.in);

		while (!userInput.hasNext())
			;

		String input = "";
		String code = "";
		if (userInput.hasNext())
			code = userInput.nextLine();

		System.out.println("input is '" + code + "'");
		if (!input.equals("")) {
			return code;
		} else {

		}
		userInput.close();
		return code;
	}

	private ForgotPasswordRequest getForgotPasswordRequest(String clientId, String username) {
		// TODO Auto-generated method stub
		ForgotPasswordRequest forgotPasswordRequest = new ForgotPasswordRequest();
		forgotPasswordRequest.setClientId(clientId);
		forgotPasswordRequest.setUsername(username);
		return forgotPasswordRequest;
	}

	private RespondToAuthChallengeRequest getRespondToAuthChallengeRequest(String clientId, String username, String x,
			String v) {

		RespondToAuthChallengeRequest r = new RespondToAuthChallengeRequest();
		r.setChallengeName(ChallengeNameType.PASSWORD_VERIFIER);
		r.setClientId(clientId);
		Map challengeResponses = new HashMap();
		challengeResponses.put("PASSWORD_CLAIM_SIGNATURE", x);
		challengeResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", v);
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.ENGLISH);
		String timestamp = sdf.format(date);
		challengeResponses.put("TIMESTAMP", timestamp);
		challengeResponses.put("USERNAME", username);

		r.setChallengeResponses(challengeResponses);
		System.out.println(r);
		return r;
	}

	private ConfirmSignUpRequest getConfirmSignUpRequest(String clientID, String username, String code) {
		ConfirmSignUpRequest signUpRequest = new ConfirmSignUpRequest();
		signUpRequest.setClientId(clientID);
		signUpRequest.setUsername(username);
		signUpRequest.setConfirmationCode(code);
		return signUpRequest;
	}

	private ConfirmForgotPasswordRequest getConfirmForgotPasswordRequest(String clientId, String username,
			String confirmationCode) {
		ConfirmForgotPasswordRequest r = new ConfirmForgotPasswordRequest();
		r.setClientId(clientId);
		r.setUsername(username);
		r.setConfirmationCode(confirmationCode);
		return r;
	}

	private InitiateAuthRequest createInitiateAuthRequest(String srp_A, String clientId, String username)
			throws IOException {
		InitiateAuthRequest req = new InitiateAuthRequest();
		req.setAuthFlow(AuthFlowType.USER_SRP_AUTH);
		req.setClientId(clientId);
		System.out.println("Client 'A': " + srp_A);
		Map<String, String> params = new HashMap<String, String>();
		params.put("USERNAME", username);

		params.put("SRP_A", srp_A);
		req.setAuthParameters(params);
		return req;
	}

	public void signUp(String userName, String password, String email, String donorId) throws NoSuchAlgorithmException {
		AWSCognitoClient client = AWSCognitoClient.getClient();
		AWSCognitoIdentityProvider provider = (AWSCognitoIdentityProvider) client.getAWSCognitoIdProvider();

		SignUpResult result = provider
				.signUp(createSignUpRequest(client.getClientId(), password, userName, email, donorId));
		System.out.println(result);
		// System.out.println(provider.adminGetUser(createAdminGetUserRequest(userName,
		// client.getUserPoolId())));

	}

	private SignUpRequest createSignUpRequest(String clientID, String password, String userName, String email,
			String donorId) throws NoSuchAlgorithmException {
		SignUpRequest request = new SignUpRequest();
		request.setPassword(password);
		request.setClientId(clientID);
		request.setUsername(userName);
		List userAttrs = new ArrayList();
		AttributeType attrType = new AttributeType();
		attrType = new AttributeType();
		attrType.setName("email");
		attrType.setValue(email);
		userAttrs.add(attrType);
		attrType = new AttributeType();
		attrType.setName("custom:donorID");
		attrType.setValue(donorId);
		userAttrs.add(attrType);
		request.setUserAttributes(userAttrs);
		return request;
	}

}