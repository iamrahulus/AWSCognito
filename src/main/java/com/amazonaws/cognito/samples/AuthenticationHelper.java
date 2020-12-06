package com.amazonaws.cognito.samples;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.amazonaws.util.StringUtils;

public class AuthenticationHelper {
	private BigInteger a;
	private BigInteger A;
	private String poolName;

	public AuthenticationHelper(String userPoolName) {
		do {
			System.out.println("Big Integer: N=" + N);
			a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
			A = g.modPow(a, N);
		} while (A.mod(N).equals(BigInteger.ZERO));

		if (userPoolName.contains("_")) {
			poolName = userPoolName.split("_", 2)[1];
		} else {
			poolName = userPoolName;
		}
	}

	public BigInteger geta() {
		return a;
	}

	public BigInteger getA() {
		return A;
	}

	private static final String HEX_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			+ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			+ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			+ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			+ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			+ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
			+ "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
			+ "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
			+ "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
	private static final BigInteger N = new BigInteger(HEX_N, 16);
	private static final BigInteger g = BigInteger.valueOf(2);
	private static final BigInteger k;

	private static BigInteger v = null;

	private static final int EPHEMERAL_KEY_LENGTH = 1024;
	private static final int DERIVED_KEY_SIZE = 16;
	private static final String DERIVED_KEY_INFO = "Caldera Derived Key";

	private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST = new ThreadLocal<MessageDigest>() {
		@Override
		protected MessageDigest initialValue() {
			try {
				return MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Exception in authentication", e);
			}
		}
	};

	private static final SecureRandom SECURE_RANDOM;

	static {
		try {
			SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

			MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
			messageDigest.reset();
			messageDigest.update(N.toByteArray());
			byte[] digest = messageDigest.digest(g.toByteArray());
			k = new BigInteger(1, digest);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	public byte[] getPasswordAuthenticationKey(String userId, String userPassword, BigInteger B, BigInteger salt) {
		// Authenticate the password
		// u = H(A, B)
		MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
		messageDigest.reset();
		messageDigest.update(A.toByteArray());
		BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
		if (u.equals(BigInteger.ZERO)) {
			throw new RuntimeException("Hash of A and B cannot be zero");
		}

		// x = H(salt | H(poolName | userId | ":" | password))
		messageDigest.reset();
		messageDigest.update(poolName.getBytes(StringUtils.UTF8));
		messageDigest.update(userId.getBytes(StringUtils.UTF8));
		messageDigest.update(":".getBytes(StringUtils.UTF8));
		byte[] userIdHash = messageDigest.digest(userPassword.getBytes(StringUtils.UTF8));

		messageDigest.reset();
		messageDigest.update(salt.toByteArray());
		BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
		BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

		// MessageDigest digest = THREAD_MESSAGE_DIGEST.get();

		Hkdf hkdf = null;
		try {
			hkdf = Hkdf.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
		hkdf.init(S.toByteArray(), u.toByteArray());
		byte[] key = hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
		return key;
	}

	public BigInteger getVerifier(String userId, String password) {
		MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
		byte[] userIdHash = messageDigest.digest(password.getBytes(StringUtils.UTF8));
		BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
		return g.modPow(x, N);
	}
}
