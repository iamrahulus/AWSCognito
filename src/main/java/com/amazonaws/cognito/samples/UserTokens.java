package com.amazonaws.cognito.samples;

import java.io.Serializable;

public class UserTokens implements Serializable {
	String accessToken;
	String refreshToken;
	String tokenType;
	String idToken;
	Integer expirationInterval;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getTokenType() {
		return tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public String getIdToken() {
		return idToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	public Integer getExpirationInterval() {
		return expirationInterval;
	}

	public void setExpirationInterval(Integer expirationInterval) {
		this.expirationInterval = expirationInterval;
	}

	public UserTokens(String accessToken, String refreshToken, String tokenType, String idToken,
			Integer expirationInterval) {
		super();
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.tokenType = tokenType;
		this.idToken = idToken;
		this.expirationInterval = expirationInterval;
	}

}
