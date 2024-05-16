package dam.psp.ex20230315;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;

public class Peticion implements Runnable {

	private Socket socket;
	private DataOutputStream out;
	
	public Peticion(Socket socket) throws IOException {
		this.socket = socket;
		socket.setSoTimeout(5000);
		out = new DataOutputStream(socket.getOutputStream());
	}

	@Override
	public void run() {
		System.out.println("Conectado con " + socket.getInetAddress());
		try (DataInputStream in = new DataInputStream(socket.getInputStream())) {
			String peticion = in.readUTF();
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void enviarRespuesta(String respuesta) {
		System.out.println(socket.getInetAddress() + " -> " + respuesta);
		try {
			out.writeUTF(respuesta);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
