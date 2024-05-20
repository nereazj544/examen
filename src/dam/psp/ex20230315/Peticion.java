package dam.psp.ex20230315;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;

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

}
