package com.codevasp.dummy.controller;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.MessageEncoder;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;

public class CodeCrypto {
	private final Logger logger = LoggerFactory.getLogger(this.getClass().getSimpleName());

//	@Value("${my.privkey}")
//	private String base64OwnSecretKey;
//	@Value("${remote.publicKey}")
//	private String base64RemotePublicKey;
	private KeyPair signKeyPair;
	private Key peerVerifyKey;
	private byte[] peerPublicKey;
	private LazySodiumJava sodium = new LazySodiumJava(new SodiumJava(), new UrlSafeBase64MessageEncoder());
	private byte[] sharedKey = new byte[Box.BEFORENMBYTES];

	//@PostConstruct
//	private void init() {
//		try {
//			sodium.sodiumInit();
//			logger.info("base64OwnSecretKey: " + base64OwnSecretKey);
//			byte[] seed = Base64.getDecoder().decode(base64OwnSecretKey);
//			signKeyPair = sodium.cryptoSignSeedKeypair(seed);
//			if (base64RemotePublicKey != null) {
//				peerVerifyKey = Key.fromBase64String(base64RemotePublicKey);
//				peerPublicKey = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
//				sodium.convertPublicKeyEd25519ToCurve25519(peerPublicKey, peerVerifyKey.getAsBytes());
//
//				KeyPair cryptoKeyPair = sodium.convertKeyPairEd25519ToCurve25519(signKeyPair);
//				if (!sodium.cryptoBoxBeforeNm(sharedKey, peerPublicKey, cryptoKeyPair.getSecretKey().getAsBytes())) {
//					throw new SodiumException("Unable to make shared key");
//				}
//			}
//		} catch (SodiumException e) {
//			e.printStackTrace();
//		}
//	}

	public CodeCrypto(String b64OwnSecretKey, String b64RemotePublicKey) {
		
		try {
			sodium.sodiumInit();
			logger.info("base64OwnSecretKey: " + b64OwnSecretKey);
			byte[] seed = Base64.getDecoder().decode(b64OwnSecretKey);
			signKeyPair = sodium.cryptoSignSeedKeypair(seed);
			
			if (! b64RemotePublicKey.isEmpty()) {
				peerVerifyKey = Key.fromBase64String(b64RemotePublicKey);
				peerPublicKey = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
				sodium.convertPublicKeyEd25519ToCurve25519(peerPublicKey, peerVerifyKey.getAsBytes());

				KeyPair cryptoKeyPair = sodium.convertKeyPairEd25519ToCurve25519(signKeyPair);
				if (!sodium.cryptoBoxBeforeNm(sharedKey, peerPublicKey, cryptoKeyPair.getSecretKey().getAsBytes())) {
					throw new SodiumException("Unable to make shared key");
				}
			}	
		} catch (SodiumException e) {
			e.printStackTrace();
		}
		
	}
	
	public String getVerifyKey() {
		return Base64.getEncoder().encodeToString(signKeyPair.getPublicKey().getAsBytes());
	}

	public byte[] sign(byte[] data) {
		byte[] signatureBytes = new byte[Sign.BYTES];
		sodium.cryptoSignDetached(signatureBytes, data, data.length, signKeyPair.getSecretKey().getAsBytes());
		return signatureBytes;
	}

	public boolean verify(String signature, String data) {
		if (peerVerifyKey == null) {
			logger.info("This CodeCrypto instance does not have peerVerifyKey, return false.");
			return false;
		}
		return sodium.cryptoSignVerifyDetached(signature, data, peerVerifyKey);
	}

	public byte[] encrypt(byte[] data) throws SodiumException, IOException {
		if (peerVerifyKey == null) {
			logger.info("This CodeCrypto instance does not have peerVerifyKey, return false.");
			return null;
		}
		byte[] nonce = sodium.randomBytesBuf(Box.NONCEBYTES);
		byte[] encrypted = new byte[data.length + Box.MACBYTES];
		if (!sodium.cryptoBoxEasyAfterNm(encrypted, data, data.length, nonce, sharedKey)) {
			throw new SodiumException("Could not encrypt data");
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(nonce);
		out.write(encrypted);
		return out.toByteArray();
	}

	public byte[] decrypt(byte[] data) throws SodiumException {
		if (peerVerifyKey == null) {
			logger.info("This CodeCrypto instance does not have peerVerifyKey, return false.");
			return null;
		}
		byte[] nonce = Arrays.copyOfRange(data, 0, Box.NONCEBYTES);
		byte[] encryptedMsg = Arrays.copyOfRange(data, Box.NONCEBYTES, data.length);
		byte[] decrypted = new byte[encryptedMsg.length - Box.MACBYTES];
		if (!sodium.cryptoBoxOpenEasyAfterNm(decrypted, encryptedMsg, encryptedMsg.length, nonce, sharedKey)) {
			throw new SodiumException("Could not decrypt data");
		}
		return decrypted;
	}

	public static class UrlSafeBase64MessageEncoder implements MessageEncoder {

		@Override
		public String encode(byte[] cipher) {
			return Base64.getEncoder().encodeToString(cipher);
		}

		@Override
		public byte[] decode(String cipherText) {
			return Base64.getDecoder().decode(cipherText);
		}
	}

	public static byte[] toBytes(int i) {
		byte[] result = new byte[4];

		result[0] = (byte) (i >> 24);
		result[1] = (byte) (i >> 16);
		result[2] = (byte) (i >> 8);
		result[3] = (byte) (i /* >> 0 */);

		return result;
	}

}
