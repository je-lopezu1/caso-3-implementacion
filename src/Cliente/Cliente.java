package Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import Servidor.KeyGenerator;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";
    private static PublicKey publicKey = null;

    public static void main(String args[]) throws IOException {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;
        KeyGenerator keyGenerator = new KeyGenerator();

        System.out.println("Cliente ...");

        try {
            // Crear el socket que se conecta al servidor
            socket = new Socket(SERVIDOR, PUERTO);

            // Crear escritor para enviar datos al servidor
            escritor = new PrintWriter(socket.getOutputStream(), true);
            
            // Crear lector para recibir datos del servidor
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        } catch (IOException e) {
            System.err.println("Exception: " + e.getMessage());
            System.exit(1);
        }

        // Crear lector para la entrada estándar del usuario
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        // Ejecutar el protocolo en el lado cliente
        
        leerLlaves();
        ProtocoloCliente.procesar(stdIn, lector, escritor, publicKey);

        // Cerrar recursos
        escritor.close();
        lector.close();
        socket.close();
        stdIn.close();
    }

    public static void leerLlaves() {
        // Leer las llaves almacenadas en los archivos
        try {

            
            byte[] publicBytes = Files.readAllBytes(Paths.get("src/Cliente/publicKeys.txt"));

            // Convertir los bytes a objetos PublicKey y PrivateKey
            byte[] decodedKey = Base64.getDecoder().decode(publicBytes);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpec);

            boolean iguales = publicKey.equals(KeyGenerator.getPublicKey());
            System.out.println("Las llaves son iguales: " + iguales);
            System.out.println(publicKey);
            //System.out.println(KeyGenerator.getPrivateKey());
            

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Error al leer las llaves: " + e.getMessage());
        }
    }
}

