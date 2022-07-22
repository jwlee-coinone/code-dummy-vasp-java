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
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.goterl.lazysodium.exceptions.SodiumException;

@Controller
public class MainPageController {
	private final Logger logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
	@Value("${my.privkey}")
	private String b64OwnSecretKey;
	
	@GetMapping("/hello")
	public String hello(@RequestParam(name="name", required=false, defaultValue="CODE") String name, Model model) {
		model.addAttribute("name", name);
		return "hello";
	}
	
	@GetMapping("/vasp")
    public String mainPage(Model model) throws JSONException, SodiumException, IOException {
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, "");
		
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
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/vasps");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");

		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
        return "vasps";
    }
	
	@GetMapping("/address/verification/global")
	public String globalAddressSearch(Model model) throws JSONException, SodiumException, IOException {
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, "P2lEVJ63ESshum0JavXufBA4WUbydnsZzVGFnCVWo/Y=");
		
		// Generating Request Body
		String body = "";
		try {
			JSONArray accountNumber = new JSONArray();
			accountNumber.put("rNZH8FPhgXa1MAYY11MQEBfWScBF4PVV24:1323392364");
			
			JSONObject beneficiary = new JSONObject();
			beneficiary.put("accountNumber", accountNumber);
			
			JSONObject ivms101 = new JSONObject();
			ivms101.put("Beneficiary", beneficiary);
			
			JSONObject payload = new JSONObject();
			payload.put("ivms101", ivms101);
			
			JSONObject bodyJson = new JSONObject();
			bodyJson.put("currency", "XRP");
			bodyJson.put("payload", payload);
			
			body = bodyJson.toString();
		} catch (JSONException e) {
			logger.error(e.getMessage());
		}
		
		
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
		
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/VerifyAddress");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		//conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
		
		if (body != null) {
			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
			conn.getOutputStream().write(body.getBytes("UTF8"));
		}
		
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
		return "Done";
	}

	@GetMapping("/address/verification/vv")
	public String vvAddressSearch(Model model) throws JSONException, SodiumException, IOException {
		// This is Foblgate(VerifyVasp) public key of DEV environment
		String base64RemotePublicKey = "IQbWufd+0BofADTJ5uh7U3+r4ILfcPwu3Bgdw6++Jwk=";
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, base64RemotePublicKey);
		
		// Generating Request Body
		String body = "";
		try {
			JSONArray accountNumber = new JSONArray();
			accountNumber.put("0x53823965d1fdb3d32172cfb8d4c48a3293a96088");
			
			JSONObject beneficiary = new JSONObject();
			beneficiary.put("accountNumber", accountNumber);
			
			JSONObject ivms101 = new JSONObject();
			ivms101.put("Beneficiary", beneficiary);
			
			JSONObject payload = new JSONObject();
			payload.put("ivms101", ivms101);
			byte[] encrypted = crypto.encrypt(payload.toString().getBytes());
			String encryptedPayload = Base64.getEncoder().encodeToString(encrypted);
			
			JSONObject bodyJson = new JSONObject();
			bodyJson.put("currency", "ETH");
			bodyJson.put("payload", encryptedPayload);
			
			body = bodyJson.toString();
			logger.info("Request Body: " + body);
		} catch (JSONException e) {
			logger.error(e.getMessage());
		}
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
		
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/VerifyAddress/16384656509591634828");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
		
		if (body != null) {
			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
			conn.getOutputStream().write(body.getBytes("UTF8"));
		}
		
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
		return "Done";
	}
	
	@GetMapping("/transfer/authorization")
	public String authorizationRequest(Model model) throws JSONException, SodiumException, IOException {
		// This is Coinone(CODE) public key of DEV environment
		String base64RemotePublicKey = "P2lEVJ63ESshum0JavXufBA4WUbydnsZzVGFnCVWo/Y=";
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, base64RemotePublicKey);
		
		// Generating Request Body
		String body = "";
		try {
//			// start initiating legalPerson Object
//			JSONObject legalNameValue = new JSONObject();
//			legalNameValue.put("legalPersonName", "(주)코인원");
//			legalNameValue.put("legalPersonNameIdentifierType", "LEGL");
//			
//			JSONArray legalNameIdentifier = new JSONArray();
//			legalNameIdentifier.put(legalNameValue);
//			
//			JSONObject legalName = new JSONObject();
//			legalName.put("nameIdentifier", legalNameIdentifier);
//			
//			JSONObject legalPerson = new JSONObject();
//			legalPerson.put("name", legalName);
//			
//			JSONObject legalPersonObj = new JSONObject();
//			legalPersonObj.put("legalPerson",legalPerson);
//			// End of initiating legalPerson Object
			
			// Start initiating naturalPerson Object
			JSONObject nameValue = new JSONObject();
			nameValue.put("primaryIdentifier", "김");
			nameValue.put("secondaryIdentifier", "지호");
			nameValue.put("nameIdentifierType", "LEGL");
			
			JSONArray nameIdentifier = new JSONArray();
			nameIdentifier.put(nameValue);
			
			// Optional
			JSONObject localName = new JSONObject();
			localName.put("primaryIdentifier", "KIM");
			localName.put("secondaryIdentifier", "JIHO");
			localName.put("nameIdentifierType", "LEGL");
			
			JSONArray localNameIdentifier = new JSONArray();
			localNameIdentifier.put(localName);
			
			JSONObject name = new JSONObject();
			name.put("nameIdentifier", nameIdentifier);
			name.put("localNameIdentifier", localNameIdentifier);
			
			JSONObject naturalPerson = new JSONObject();
			naturalPerson.put("name", name);
			
			JSONObject naturalPersonObj = new JSONObject();
			naturalPersonObj.put("naturalPerson", naturalPerson);
			// End of initiating naturalPerson Object
			
			// Start initiating originatorPersons Array Object
			JSONArray originatorPersons = new JSONArray();
			// Order of Objects is important. legalPerson -> naturalPerson -> naturalPerson2 ...
			//originatorPersons.put(0, legalPersonObje);
			originatorPersons.put(naturalPersonObj);
			// End of initiating originatorPersons Array Object
			
			JSONArray accountNumber = new JSONArray();
			accountNumber.put("rNZH8FPhgXa1MAYY11MQEBfWScBF4PVV24:1323392364");
			
			// Start initiating Originator Object
			JSONObject originator = new JSONObject();
			originator.put("originatorPersons", originatorPersons);
			originator.put("customerIdentification", "User Id");
			originator.put("accountNumber", accountNumber);
			// End of initiating Originator Object
			
			
			// Start initiating naturalPerson Object
			JSONObject beneficiaryNameValue = new JSONObject();
			beneficiaryNameValue.put("primaryIdentifier", "김");
			beneficiaryNameValue.put("secondaryIdentifier", "지호");
			beneficiaryNameValue.put("nameIdentifierType", "LEGL");
			
			JSONArray beneficiaryNameIdentifier = new JSONArray();
			beneficiaryNameIdentifier.put(nameValue);
			
			// Optional
			JSONObject beneficiaryLocalName = new JSONObject();
			beneficiaryLocalName.put("primaryIdentifier", "KIMJIHO");
			beneficiaryLocalName.put("nameIdentifierType", "LEGL");
			
			JSONArray beneficiaryLocalNameIdentifier = new JSONArray();
			beneficiaryLocalNameIdentifier.put(localName);
			
			JSONObject beneficiaryName = new JSONObject();
			beneficiaryName.put("nameIdentifier", nameIdentifier);
			beneficiaryName.put("localNameIdentifier", localNameIdentifier);
			
			JSONObject beneficiaryNaturalPerson = new JSONObject();
			beneficiaryNaturalPerson.put("name", name);
			
			JSONObject beneficiaryNaturalPersonObj = new JSONObject();
			beneficiaryNaturalPersonObj.put("naturalPerson", naturalPerson);
			// End of initiating naturalPerson Object
			
			JSONArray beneficiaryPersons = new JSONArray();
			// Order of Objects is important. legalPerson -> naturalPerson -> naturalPerson2 ...
			beneficiaryPersons.put(naturalPersonObj);
			// End of initiating beneficiaryPersons Array Object
			
			JSONArray beneficiaryAccountNumber = new JSONArray();
			beneficiaryAccountNumber.put("rNZH8FPhgXa1MAYY11MQEBfWScBF4PVV24:1323392364");
			
			// Start initiating Beneficiary Object
			JSONObject beneficiary = new JSONObject();
			beneficiary.put("beneficiaryPersons", beneficiaryPersons);
			beneficiary.put("customerIdentification", "User Id");
			beneficiary.put("accountNumber", beneficiaryAccountNumber);
			// End of initiating Beneficiary Object
			
			
			
			
			JSONObject originVaspNameValue = new JSONObject();
			originVaspNameValue.put("legalPersonName", "Robot VASP");
			originVaspNameValue.put("legalPersonNameIdentifierType", "LEGL");
			
			JSONArray originVaspNameIdentifier = new JSONArray();
			originVaspNameIdentifier.put(originVaspNameValue);
			
			JSONObject originVaspName = new JSONObject();
			originVaspName.put("nameIdentifier", originVaspNameIdentifier);
			
			
			
			JSONArray addressLine = new JSONArray();
			addressLine.put(0, "14 Teheran-ro 4-gil, Gangnam-gu");
			addressLine.put(1, "4th floor");
			
			JSONObject geoAddressObj = new JSONObject();
			geoAddressObj.put("addressType",  "GEOG");
			geoAddressObj.put("townName", "Seoul");
			geoAddressObj.put("addressLine", addressLine);
			geoAddressObj.put("country", "KR");
			
			JSONArray geoAddress = new JSONArray();
			geoAddress.put(0, geoAddressObj);
			
			
			
			JSONObject nationalIdentification = new JSONObject();
			nationalIdentification.put("nationalIdentifier", "사업자 등록번호");
			nationalIdentification.put("nationalIdentifierType", "RAID");
			nationalIdentification.put("registrationAuthority", "RA000657");
			
			JSONObject originVaspLegalPerson = new JSONObject();
			originVaspLegalPerson.put("name", originVaspName);
			originVaspLegalPerson.put("geographicAddress", geoAddress);
			originVaspLegalPerson.put("nationalIdentification", nationalIdentification);
			originVaspLegalPerson.put("countryOfRegistration", "KR");
			
			
			
			JSONObject originVaspOriginatingVasp = new JSONObject();
			originVaspOriginatingVasp.put("legalPerson", originVaspLegalPerson);
			
			
			JSONObject originatingVasp = new JSONObject();
			originatingVasp.put("originatingVASP", originVaspOriginatingVasp);
			
			
			JSONObject ivms101 = new JSONObject();
			ivms101.put("Originator", originator);
			ivms101.put("Beneficiary", beneficiary);
			ivms101.put("OriginatingVASP", originatingVasp);
			logger.info("Plain Request Body: " + ivms101.toString());
			
			
			JSONObject payload = new JSONObject();
			payload.put("ivms101", ivms101);
			byte[] encrypted = crypto.encrypt(payload.toString().getBytes());
			String encryptedPayload = Base64.getEncoder().encodeToString(encrypted);
			
			
			
			JSONObject bodyJson = new JSONObject();
			bodyJson.put("currency", "XRP");
			bodyJson.put("transferId", UUID.randomUUID().toString()); // Generate UUID v4 random ID
			bodyJson.put("amount", "1111.11");
			bodyJson.put("tradePrice", "2000000");
			bodyJson.put("tradeCurrency", "KRW");
			bodyJson.put("isExceedingThreshold", "true");
			bodyJson.put("payload", encryptedPayload);
			
			body = bodyJson.toString();
			logger.info("Request Body: " + body);
		} catch (JSONException e) {
			logger.error(e.getMessage());
		}
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
		
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/transfer/coinone");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
		
		if (body != null) {
			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
			conn.getOutputStream().write(body.getBytes("UTF8"));
		}
		
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
		return "Done";
	}
	
	
	@GetMapping("/transfer/txid")
	public String reportTxid(Model model) throws JSONException, SodiumException, IOException {
		// This is Coinone(CODE) public key of DEV environment
		String base64RemotePublicKey = "P2lEVJ63ESshum0JavXufBA4WUbydnsZzVGFnCVWo/Y=";
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, base64RemotePublicKey);
				
		// Generating Request Body
		String body = "";
		try {
			JSONObject request = new JSONObject();
			request.put("transferId", "abb030cf-61e5-4dae-b8c3-7441a5bc9b3b");
			request.put("txid", "311BFF73D9B7969CCF1042186180159C724FAB59013A7A034A93E5FB9D6BAFE6");
			request.put("vout", "");
			body = request.toString();
		} catch (JSONException e) {
			logger.error(e.getMessage());
		}
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
				
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/transfer/coinone/txid");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoInput(true);
		conn.setDoOutput(true);
				
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
				
		if (body != null) {
			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
			conn.getOutputStream().write(body.getBytes("UTF8"));
		}
		
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
		return "Done";
		
	}

	
	@GetMapping("/transfer/status")
	public String finishTransfer(Model model) throws JSONException, SodiumException, IOException {
		// This is Coinone(CODE) public key of DEV environment
		String base64RemotePublicKey = "P2lEVJ63ESshum0JavXufBA4WUbydnsZzVGFnCVWo/Y=";
		CodeCrypto crypto = new CodeCrypto(b64OwnSecretKey, base64RemotePublicKey);
				
		// Generating Request Body
		String body = "";
		try {
			JSONObject request = new JSONObject();
			request.put("transferId", "abb030cf-61e5-4dae-b8c3-7441a5bc9b3b");
			request.put("status", "canceled");
			request.put("reasonType", "SANCTION_LIST");
			body = request.toString();
		} catch (JSONException e) {
			logger.error(e.getMessage());
		}
		
		// Generating Signature
		int iNonce = (int)(Math.random() * 10000);
				
		Calendar calendar = Calendar.getInstance();
		Date date = calendar.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String strDateTime = sdf.format(date);
		
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		buffer.write(strDateTime.getBytes());
		buffer.write(body.getBytes());
		buffer.write(CodeCrypto.toBytes(iNonce));
		
		byte[] signature = crypto.sign(buffer.toByteArray());
		String signatureBase64 = Base64.getEncoder().encodeToString(signature);
		
		URL url = new URL("https://trapi-dev.codevasp.com/v1/code/transfer/coinone/status");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoInput(true);
		conn.setDoOutput(true);
				
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("X-Code-Req-PubKey", crypto.getVerifyKey());
		conn.setRequestProperty("X-Code-Req-Signature", signatureBase64);
		conn.setRequestProperty("X-Code-Req-Datetime",  strDateTime);
		conn.setRequestProperty("X-Code-Req-Nonce", String.valueOf(iNonce));
		conn.setRequestProperty("X-Request-Origin", "code:dummy");
		conn.setRequestProperty("X-Code-Req-Remote-PubKey", base64RemotePublicKey);
				
		if (body != null) {
			conn.setRequestProperty("Content-Length", Integer.toString(body.length()));
			conn.getOutputStream().write(body.getBytes("UTF8"));
		}
		
		conn.connect();
		
		// 보내고 결과값 받기
		int responseCode = conn.getResponseCode();
		logger.info("responseCode: " + responseCode);
		
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
				logger.info("vaspData: " + gson.toJson(je));
				model.addAttribute("vaspData", receivedMessage.toString());
			} catch (JSONException e) {
				logger.error(e.getMessage());
				logger.error(strCurrentLine);
			}
		}
		return "Done";
		
	}

}


