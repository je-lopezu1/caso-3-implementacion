package Servidor;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


public class Servidor{
    private static ServerSocket ss = null;
    private static boolean continuar = true;
    private static int numeroThreads = 0; // Variable para controlar los identificadores de los threads

    private static PrivateKey privateKey;

    public static void main(String args[]) {

        Scanner scanner = new Scanner(System.in);
            int opcion;

            do {
                System.out.println("Menú de opciones:");
                System.out.println("1. Opción 1");
                System.out.println("2. Opción 2");
                System.out.println("0. Salir");
                System.out.print("Seleccione una opción: ");

                opcion = scanner.nextInt();

                switch (opcion) {
                    case 1:
                        System.out.println("Has seleccionado Opción 1.");
                        // Lógica para la Opción 1
                        opcion1();
                        break;
                    case 2:
                        System.out.println("Has seleccionado Opción 2.");
                        // Lógica para la Opción 2
                        iniciarServidor();
                        opcion2(args);
                        break;
                    case 0:
                        System.out.println("Saliendo del programa.");
                        break;
                    default:
                        System.out.println("Opción no válida. Intente de nuevo.");
                }

                System.out.println(); // Espacio adicional para mejor legibilidad
            } while (opcion != 0);

            scanner.close();

            
            /*File publicKeysFile = new File("src/Cliente/publicKeys.txt");
                File privateKeysFile = new File("src/Servidor/privateKeys.txt");

                if (publicKeysFile.exists() && publicKeysFile.delete()) {
                    System.out.println("Archivo de llaves públicas eliminado.");
                } else {
                    System.err.println("No se pudo eliminar el archivo de llaves públicas.");
                }

                if (privateKeysFile.exists() && privateKeysFile.delete()) {
                    System.out.println("Archivo de llaves privadas eliminado.");
                } else {
                    System.err.println("No se pudo eliminar el archivo de llaves privadas.");
            }*/
        
    }

    public static void iniciarServidor() {

        System.out.println("Servidor creado ...");

        try {
            ss = new ServerSocket(3400); // Aquí va el número de puerto
        } catch (IOException e) {
            System.err.println("No se pudo crear el socket en el puerto: 3400"); // Aquí va el número de puerto
            System.exit(-1);
        }
    }

    public static void opcion1() {
            KeyGenerator.generateAndStoreKeys();
        }

    public static void opcion2(String args[]) {
        // Lógica para la Opción 2
        leerLlaves();
        while (continuar) {
            // crear el socket
            Socket socket = null;
            try {
                socket = ss.accept();
            } catch (IOException e) {
                System.err.println("Error al aceptar la conexión: " + e.getMessage());
                continue;
            }
    
            // crear el thread con el socket y el id
            ThreadServidor thread = new ThreadServidor(socket, numeroThreads, privateKey);
            numeroThreads++; // Incrementa el identificador para que cada thread tenga uno diferente
    
            // iniciar el thread
            thread.start();
        }
        try {
            ss.close();
        } catch (IOException e) {
            System.err.println("Error al cerrar el ServerSocket: " + e.getMessage());
        }
    }

    public static void leerLlaves() {
        // Leer las llaves almacenadas en los archivos
        try {
            System.out.println(KeyGenerator.getPublicKey());
            byte[] privateBytes = Files.readAllBytes(Paths.get("src/Servidor/privateKeys.txt"));
            byte[] decodedKey = Base64.getDecoder().decode(privateBytes);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            privateKey = keyFactory.generatePrivate(keySpec);

            // Sin iguales las llaves?
            boolean iguales = privateKey.equals(KeyGenerator.getPrivateKey());
            System.out.println("Las llaves son iguales: " + iguales);
            //System.out.println(privateKey);
            
            

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Error al leer las llaves: " + e.getMessage());
        }
    }
}
