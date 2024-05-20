package dam.psp.ex20230315;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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

				break;
			case "cifrar":

				break;
			default:
				enviarRespuesta(String.format("ERROR:'%s' no se reconoce como una petición válida", peticion));
			}
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba una petición");
		} catch (IOException e) {
			e.printStackTrace();
			try {
				socket.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
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
//			e.printStackTrace();
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
			e.printStackTrace();
		} 
	}

}
