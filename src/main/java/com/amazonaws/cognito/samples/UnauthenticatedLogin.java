package com.amazonaws.cognito.samples;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClientBuilder;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityResult;
import com.amazonaws.services.cognitoidentity.model.GetIdRequest;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;

public class UnauthenticatedLogin {

	Credentials credentials = new Credentials();

	public UnauthenticatedLogin() {

	}

	public static void main(String args[]) throws FileNotFoundException, IOException, ParseException {
		UnauthenticatedLogin l = new UnauthenticatedLogin();
		l.login("<Identity pool ID>");
	}

	public Credentials authenticate(String identityPool) throws FileNotFoundException, IOException, ParseException {
		if (identityPool == null || identityPool.trim().isEmpty()) {
			throw new RuntimeException("Identity Pool cannot be null or empty");
		}
		login(identityPool);
		return this.credentials;
	}

	private void login(String identityPoolId) throws FileNotFoundException, IOException, ParseException {

		if (!cachedCredentials(identityPoolId)) {

			AmazonCognitoIdentity client = AmazonCognitoIdentityClientBuilder.standard()
					.withRegion(Regions.AP_SOUTHEAST_2).withCredentials(new EnvironmentVariableCredentialsProvider())
					.build();

			GetIdRequest request = new GetIdRequest();

			request.setIdentityPoolId(identityPoolId);

			GetIdResult result = client.getId(request);

			String identityId = result.getIdentityId();

			GetCredentialsForIdentityRequest getCredentialsForIdentityRequest = new GetCredentialsForIdentityRequest();
			getCredentialsForIdentityRequest.setIdentityId(identityId);
			GetCredentialsForIdentityResult getCredentialsForIdentityResult = client
					.getCredentialsForIdentity(getCredentialsForIdentityRequest);
			this.credentials = getCredentialsForIdentityResult.getCredentials();

			System.out.println(this.credentials);
			cacheCredentials(identityPoolId);

		} else {
			System.out.println("Printing cached credentials...");
			System.out.println(this.credentials);
		}

	}

	private void cacheCredentials(String identityPoolId) throws FileNotFoundException, IOException {
		// TODO Auto-generated method stub
		System.out.println(this.credentials);
		Properties props = new Properties();
		props.setProperty("ACCESS_KEY_ID", credentials.getAccessKeyId());
		props.setProperty("SECRET_ACCESS_KEY", credentials.getSecretKey());
		props.setProperty("SESSION_TOKEN", credentials.getSessionToken());
		props.setProperty("EXPIRATION_DATE", credentials.getExpiration().toString());
		props.store(new FileOutputStream(new File(getFileName(identityPoolId))), "Some Comments");
	}

	private boolean cachedCredentials(String identityPoolId) throws FileNotFoundException, IOException, ParseException {
		// TODO Auto-generated method stub
		File cache = new File(getFileName(identityPoolId));
		Properties props = new Properties();
		if (cache.exists()) {
			props.load(new FileInputStream(cache));
			if (props.getProperty("ACCESS_KEY_ID") != null && props.getProperty("SECRET_ACCESS_KEY") != null
					&& props.getProperty("SESSION_TOKEN") != null && props.getProperty("EXPIRATION_DATE") != null) {
				if (!isCredentialsExpired(props.getProperty("EXPIRATION_DATE"))) {
					System.out.println("Credentials in Cache still valid...");
					credentials.setAccessKeyId(props.getProperty("ACCESS_KEY_ID"));
					credentials.setSecretKey(props.getProperty("SECRET_ACCESS_KEY"));
					credentials.setSessionToken(props.getProperty("SESSION_TOKEN"));

					Date expiration = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy")
							.parse(props.getProperty("EXPIRATION_DATE"));
					credentials.setExpiration(expiration);
				} else {
					System.out.println("Credentials in Cache Expired. Refreshing the creds...");
					return false;
				}

			} else {
				cache.createNewFile();
				return false;
			}
		} else {
			cache.createNewFile();
			return false;
		}
		return true;

	}

	private boolean isCredentialsExpired(String expirationDate) throws ParseException {
		// TODO Auto-generated method stub
		Date expiration = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy")
				.parse(expirationDate);
		long expiryTime = expiration.getTime();
		long now = new Date().getTime();
		if (expiryTime <= now) {
			return true;
		}
		return false;
	}

	private String getFileName(String identityPoolId) {
		// TODO Auto-generated method stub
		return identityPoolId.substring(identityPoolId.indexOf(":") + 1);
	}
}
