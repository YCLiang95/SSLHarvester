package proj5;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;

import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

public class SSLHarvester {
	private static final boolean debug = false;
	private static final boolean debug_response = false;
	//provided by the assignment
	
	public static void getCert(String address) {
		String host;
		int port;
		URL url;
		
		try{
			host = address.substring(0, address.indexOf(":"));
			port = Integer.parseInt(address.substring(address.indexOf(":") + 1));
			url = new URL("https://" + address);
			if (debug) {
				System.out.println("url: " + host + " port: " + port);
			}
			System.out.println(address);
		} catch (Exception e) {
			System.out.println("Error prasing address for " + address + " Reason: " + e.getMessage());
			return;
		}
		
		try {
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			connection.connect();
			
			//provided by the assignment
			//From https://www.baeldung.com/java-ssl
			//SSLSocketFactory sslsocketfactory = connection.getSSLSocketFactory();
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(host, port);

			
			SSLSession session = sslsocket.getSession();
			System.out.println("CipherSuite: " + session.getCipherSuite());
			X509Certificate[] certs = session.getPeerCertificateChain();
			for (X509Certificate cert : certs) {
				System.out.println("Subject: " + cert.getSubjectDN());
				System.out.println("Issuer: " + cert.getIssuerDN());
			}
			
			BufferedReader in = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
			BufferedWriter out = new BufferedWriter (new OutputStreamWriter (sslsocket.getOutputStream()));
			String REQUEST_BUFFER = "GET /robots.txt HTTP/1.1\r\n" +
			        "Host: " + address + "\r\n" +
			        "\r\n";
			out.write(REQUEST_BUFFER);
			out.flush();
			if (debug_response) {
				String s;
				while ((s = in.readLine()) != null) {
					System.out.print(s);
				}
			}
			System.out.println("Response: " + in.readLine());
			in.close();
			
			
			if (debug) {
				System.out.println(REQUEST_BUFFER);
			}
		} catch (Exception e) {
			System.out.println("" + address + " Reason: " + e.getMessage());
			return;
		}
	}
	
	public static void main (String args[]) {
		if (debug) {
			getCert("www.google.com:443");
		}
		for (String i : args) {
			getCert(i);
		}
	}

}
