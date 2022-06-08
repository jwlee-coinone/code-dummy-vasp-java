package com.codevasp.dummy.controller;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.goterl.lazysodium.exceptions.SodiumException;

import org.springframework.beans.factory.annotation.Value;

@RestController
public class MainPageController {
	private final Logger logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
	
	@RequestMapping("/")
    public String mainPage() throws JSONException, SodiumException, IOException {
		//CodeCrypto crypto = new CodeCrypto();
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
		
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		//buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = codeCrypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		//URL url = new URL("https://test-api-codevasp.gamevilcom2us.com/v1/code/VerifyAddress");
		URL url = new URL("https://test-api-codevasp.gamevilcom2us.com/v1/code/vasps");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", codeCrypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		//conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
		
//		if (body != null) {
//			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
//			conn.getOutputStream().write(body.getBytes("UTF8"));
//		}
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		System.out.println("responseCode: " + responseCode);
		
		BufferedReader br = null;
		String strCurrentLine;
		br = new BufferedReader(new InputStreamReader(responseCode == 200 ? conn.getInputStream():conn.getErrorStream()));
		while ((strCurrentLine = br.readLine()) != null) {
			try {
				JSONObject receivedMessage = new JSONObject(strCurrentLine);
				if(receivedMessage.has("payload") &&
					!receivedMessage.get("payload").getClass().getName().equals("org.json.JSONObject")) {
					String encryptedPayload = receivedMessage.getString("payload");
					byte[] encData = Base64.getDecoder().decode(encryptedPayload);
					byte[] decrypted = crypto.decrypt(encData);
					String decryptedString = new String(decrypted);
					JSONObject objPayload = new JSONObject(decryptedString);
					receivedMessage.put("payload",  objPayload);
				}
				Gson gson = new GsonBuilder().setPrettyPrinting().create();
				JsonParser jp = new JsonParser();
				JsonElement je = jp.parse(receivedMessage.toString());
				return gson.toJson(je);
			} catch (JSONException e) {
			    System.out.println(e.getMessage());
			    System.out.println(strCurrentLine);
			}
		}
        return "Hello World.";
    }
}
