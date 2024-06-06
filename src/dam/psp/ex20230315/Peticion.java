package dam.psp.ex20230315;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.UTFDataFormatException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Peticion implements Runnable {

	private final Socket socket;
	private DataOutputStream out;
	private DataInputStream in;

	public Peticion(Socket socket) throws IOException {
		this.socket = socket;
		socket.setSoTimeout(5000);
		out = new DataOutputStream(socket.getOutputStream());
		in = new DataInputStream(socket.getInputStream());
	}

	@Override
	public void run() {
		System.out.println("Conectado con " + socket.getInetAddress());
		try {
			String peticion = in.readUTF();
			switch (peticion) {
			case "hash":
				peticionHash();
				break;
			case "cert":
				peticionCert();
				break;
			case "cifrar":
				peticionCifrar();
				break;
			default:
				enviarRespuesta(String.format("ERROR:'%s' no se reconoce como una petición válida", peticion));
			}
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba una petición");
		} catch (IOException e) {
			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
		}
	}

	private void enviarRespuesta(String respuesta) {
		System.out.println(socket.getInetAddress() + " -> " + respuesta);
		try (socket) {
			out.writeUTF(respuesta);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

//	private void peticionHash() {
//		try {
//			String algoritmo = in.readUTF();
//			MessageDigest md = MessageDigest.getInstance(algoritmo);
//			byte [] bytes = in.readAllBytes();
//			if (bytes.length == 0)
//				enviarRespuesta("ERROR:Se esperaban datos");
//			else {
//				byte [] hash = md.digest(bytes);
//				enviarRespuesta("OK:" + Base64.getEncoder().encodeToString(hash));
//			}
//		} catch (SocketTimeoutException e) {
//			enviarRespuesta("ERROR:Read timed out");
//		} catch (EOFException | NoSuchAlgorithmException e) {
//			enviarRespuesta("ERROR:Se esperaba un algoritmo");
//		} catch (IOException e) {
//			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
//		} 
//	}
	
	private void peticionHash() {
		try {
			String algoritmo = in.readUTF();
			MessageDigest md = MessageDigest.getInstance(algoritmo);
			int n;
			int contador = 0;
			byte [] bytes = new byte[1024];
			while ((n = in.read(bytes)) != -1) {
				contador += n;
				md.update(bytes, 0, n);
			}
			if (contador == 0)
				enviarRespuesta("ERROR:Se esperaban datos");
			else
				enviarRespuesta("OK:" + Base64.getEncoder().encodeToString(md.digest()));
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException | NoSuchAlgorithmException e) {
			enviarRespuesta("ERROR:Se esperaba un algoritmo");
		} catch (IOException e) {
			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
		} 
	}
	
	private void peticionCert() {
		try {
			String alias = in.readUTF();
			try {
				String certB64 = in.readUTF(); 
				byte [] certEncoded = Base64.getDecoder().decode(certB64);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certEncoded));
				Servidor.ks.setCertificateEntry(alias, cert);
				enviarRespuesta("OK:" +
						Base64.getEncoder().encodeToString(
								MessageDigest.getInstance("SHA-256").digest(certB64.getBytes())));
			} catch (EOFException | UTFDataFormatException | SocketTimeoutException e) {
				enviarRespuesta("ERROR:Se esperaba un certificado");
			} catch (IllegalArgumentException e) {
				enviarRespuesta("ERROR:Se esperaba Base64");
			} catch (CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
				enviarRespuesta("ERROR:" + e.getLocalizedMessage());
			} 
		} catch (EOFException | UTFDataFormatException | SocketTimeoutException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (IOException e) {
			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
		}
	}

	private void peticionCifrar() {
		try {
			String alias = in.readUTF();
			try {
				Certificate cert = Servidor.ks.getCertificate(alias);
				if (cert != null) {
					PublicKey key = cert.getPublicKey();
					if (key.getAlgorithm().equals("RSA")) {
						cifrar(key);
					}
					else
						enviarRespuesta(String.format("ERROR:'%s' no contiene una clave RSA", alias));
				}
				else
					enviarRespuesta(String.format("ERROR:'%s' no es un certificado", alias));
			} catch (KeyStoreException e) {
				enviarRespuesta("ERROR:" + e.getLocalizedMessage());
			}
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (UTFDataFormatException e) {
			enviarRespuesta("ERROR:formato alias incorrecto");
		} catch (IOException e) {
			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
		}
	}
	
	private void cifrar(PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte [] buffer = new byte[256];
			int n;
			int total = 0;
			while ((n = in.read(buffer)) != -1) {
				total += n;
				byte [] cifrado = cipher.doFinal(buffer, 0, n);
				String b64 = Base64.getEncoder().encodeToString(cifrado);
				out.writeUTF("OK:" + b64);
			}
			if (total > 0)
				enviarRespuesta("FIN:CIFRADO");
			else
				enviarRespuesta("ERROR:Se esperaban datos");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
				 IOException | IllegalBlockSizeException | BadPaddingException e) {
			enviarRespuesta("ERROR:" + e.getLocalizedMessage());
		}
	}
	
}
