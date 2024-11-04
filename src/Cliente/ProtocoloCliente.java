package Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class ProtocoloCliente {
    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publicKey) throws IOException {
        String fromServer;
        String fromUser;

        boolean ejecutar = true;

        while (ejecutar) {
            BigInteger reto = new BigInteger(256, new java.util.Random());
            byte[] retoCifrado = cifrarReto(reto, publicKey);

            fromUser = retoCifrado.toString();

            // si el usuario no ingresó null
            if (fromUser != null) {
                System.out.println("El usuario escribió: " + fromUser);
                
                // si el mensaje ingresado es "OK", detiene la ejecución
                if (fromUser.equalsIgnoreCase("OK")) {
                    ejecutar = false;
                }

                // envía el mensaje al servidor
                pOut.println(fromUser);
            }

            // lee la respuesta del servidor
            if ((fromServer = pIn.readLine()) != null) {
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
            ejecutar = false;
        }
    }

    // Método para cifrar un BigInteger con la llave pública de un cliente
    public static byte[] cifrarReto(BigInteger message, PublicKey publicKey) {
        try {
            // Convertir el BigInteger a un arreglo de bytes
            byte[] messageBytes = message.toByteArray();

            // Configurar el cifrador con el algoritmo RSA y la llave pública
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Cifrar el mensaje
            byte[] encryptedBytes = cipher.doFinal(messageBytes);
            return encryptedBytes;
        } catch (Exception e) {
            System.err.println("Error al cifrar el mensaje: " + e.getMessage());
            return null;
        }
    }
}

