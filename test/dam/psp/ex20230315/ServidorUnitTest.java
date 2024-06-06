package dam.psp.ex20230315;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.MethodName.class)
class ServidorUnitTest {

	static KeyStore ks;
	
	@BeforeAll
	static void setUpBeforeClass() throws Exception {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(ServidorUnitTest.class.getResourceAsStream("/keystore.p12"), "practicas".toCharArray());
	}
	
	@Test
	@DisplayName("(0,2 puntos) No se envía petición (A)")
	void test01() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			String respuesta = new DataInputStream(socket.getInputStream()).readUTF();
			assertEquals("ERROR:Read timed out", respuesta);
		} catch (IOException e) {
			e.printStackTrace();
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) No se envía petición (B)")
	void test02() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			socket.shutdownOutput();
			assertEquals("ERROR:Se esperaba una petición", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición incorrecta (A)")
	void test03() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("abcd");
			assertEquals("ERROR:'abcd' no se reconoce como una petición válida", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición incorrecta (B)")
	void test04() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("abcd");
			socket.shutdownOutput();
			assertEquals("ERROR:'abcd' no se reconoce como una petición válida", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(1,4 puntos) Petición \"hash\"")
	void test05() {
		String mensaje = "MENSAJE DE PRUEBA";
		for (String algoritmo: new String [] {"SHA-256", "MD5", "SHA3-512"}) {
			try (Socket socket = new Socket("localhost", 9000)){
				socket.setSoTimeout(1000);
				MessageDigest md;
				md = MessageDigest.getInstance(algoritmo);
				String hashB64 = Base64.getEncoder().encodeToString(md.digest(mensaje.getBytes()));
				
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				out.writeUTF("hash");
				out.writeUTF(algoritmo);
				out.write(mensaje.getBytes());
				socket.shutdownOutput();
				assertEquals("OK:" + hashB64, new DataInputStream(socket.getInputStream()).readUTF());
			} catch (IOException | NoSuchAlgorithmException e) {
				fail(e.getLocalizedMessage());
			}
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin algoritmo (A)")
	void test06() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin algoritmo (B)")
	void test07() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaba un algoritmo", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos (A)")
	void test08() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos (B)")
	void test09() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaban datos", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" cliente no envía EOF")
	void test10() {
		String mensaje = "MENSAJE DE PRUEBA";
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			out.write(mensaje.getBytes());
			
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(1,4 puntos) Petición \"cert\"")
	void test11() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(1000);
			String b64 = Base64.getEncoder().encodeToString(ks.getCertificate("psp").getEncoded());
			MessageDigest md;
			md = MessageDigest.getInstance("SHA-256");
			md.update(b64.getBytes());
			String b64HashB64 = Base64.getEncoder().encodeToString(md.digest());
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF(b64);
			socket.shutdownOutput();
			
			assertEquals("OK:" + b64HashB64, new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias (A)")
	void test12() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			
			assertEquals("ERROR:Se esperaba un alias", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}	
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias (B)")
	void test13() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaba un alias", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado (A)")
	void test14() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			
			assertEquals("ERROR:Se esperaba un certificado", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado (B)")
	void test15() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaba un certificado", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" envía datos sin codificar en Base64 (B)")
	void test16() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF("*****");
			
			assertEquals("ERROR:Se esperaba Base64", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(3 puntos) Petición \"cifrar\"")
	void test17() {
		try (Socket socket = new Socket("localhost", 9000)) {
			socket.setSoTimeout(10000);
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho\r\n"
					+ "tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua,\r\n"
					+ "rocín flaco y galgo corredor. Una olla de algo más vaca que carnero,\r\n"
					+ "salpicón las más noches, duelos y quebrantos los sábados, lantejas los\r\n"
					+ "viernes, algún palomino de añadidura los domingos, consumían las tres\r\n"
					+ "partes de su hacienda. El resto della concluían sayo de velarte, calzas de\r\n"
					+ "velludo para las fiestas, con sus pantuflos de lo mesmo, y los días de\r\n"
					+ "entresemana se honraba con su vellorí de lo más fino. Tenía en su casa una\r\n"
					+ "ama que pasaba de los cuarenta, y una sobrina que no llegaba a los veinte,\r\n"
					+ "y un mozo de campo y plaza, que así ensillaba el rocín como tomaba la\r\n"
					+ "podadera. Frisaba la edad de nuestro hidalgo con los cincuenta años; era de\r\n"
					+ "complexión recia, seco de carnes, enjuto de rostro, gran madrugador y amigo\r\n"
					+ "de la caza. Quieren decir que tenía el sobrenombre de Quijada, o Quesada,\r\n"
					+ "que en esto hay alguna diferencia en los autores que deste caso escriben;\r\n"
					+ "aunque, por conjeturas verosímiles, se deja entender que se llamaba\r\n"
					+ "Quejana. Pero esto importa poco a nuestro cuento; basta que en la narración\r\n"
					+ "dél no se salga un punto de la verdad.";
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			assertEquals(texto, descifrar(new DataInputStream(socket.getInputStream())));
		} catch (Exception e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	static String descifrar(DataInputStream in) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		PrivateKey key = (PrivateKey) ks.getKey("psp", "practicas".toCharArray());
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte [] descifrado = new byte[0];
		while (true)
			try {
				String [] respuesta = in.readUTF().split(":");
				if (respuesta.length != 2)
					fail("respuesta incorrecta");
				else if (respuesta[0].equals("OK")) {
					byte[] cifrado = Base64.getDecoder().decode(respuesta[1]);
					byte[] bloque = cipher.doFinal(cifrado);
					descifrado = Arrays.copyOf(descifrado, descifrado.length + bloque.length);
					System.arraycopy(bloque, 0, descifrado, descifrado.length - bloque.length, bloque.length);
				} else if (!respuesta[0].equals("FIN") || !respuesta[1].equals("CIFRADO"))
					fail("respuesta incorrecta");
			} catch (EOFException e) {
				break;
			}
		return new String(descifrado);
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias (A)")
	void test18() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias (B)")
	void test19() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaba un alias", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el alias no es válido")
	void test20() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("aliasnoválido");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			
			assertEquals("ERROR:'aliasnoválido' no es un certificado", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el certificado no contiene una clave RSA")
	void test21() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(1000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("alumno");
			out.writeUTF(Base64.getEncoder().encodeToString(ks.getCertificate("alumno").getEncoded()));
			
			new DataInputStream(socket.getInputStream()).readUTF();
		} catch (IOException | CertificateEncodingException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}
		
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("alumno");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			
			assertEquals("ERROR:'alumno' no contiene una clave RSA", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" cliente no envía EOF")
	void test22() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			String s = null;
			try {
				while (true)
					s = in.readUTF();
			} catch (EOFException e) {
				assertTrue(s != null);
				assertEquals("ERROR:Read timed out", s);
			}
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos (A)")
	void test23() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			
			assertEquals("ERROR:Read timed out", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos (B)")
	void test24() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			socket.shutdownOutput();
			
			assertEquals("ERROR:Se esperaban datos", new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}

} 
