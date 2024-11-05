package Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class ProtocoloCliente {
    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publicKey) throws IOException {
        String fromServer;
        String fromUser;

        boolean ejecutar = true;

        while (ejecutar) {
            //VERIFICACIÓN DE RETO
            BigInteger reto = new BigInteger(256, new java.util.Random());
            byte[] retoCifrado = cifrarReto(reto, publicKey);
            String retoCifradoStr = Base64.getEncoder().encodeToString(retoCifrado);
            //manda mensaje cifrado al servidor
            fromUser = retoCifradoStr;
            pOut.println(fromUser);
            // lee la respuesta del servidor
            if ((fromServer = pIn.readLine()) != null) {
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
            byte[] rtaBytes = Base64.getDecoder().decode(fromServer);
            BigInteger rtaConverted = new BigInteger(rtaBytes);
            boolean verificacion = reto.equals(rtaConverted);
            if (!verificacion)
            {
                fromUser = "ERROR";
                pOut.println(fromUser);
                break;
            }
            else
            {
                fromUser = "OK";
                pOut.println(fromUser);
            }
            //VERIFICACIÓN DE LA FIRMA
            String Pstring = pIn.readLine(); 
            byte[] Pbytes = Base64.getDecoder().decode(Pstring);
            BigInteger P = new BigInteger(Pbytes);
            String Gstring = pIn.readLine(); 
            byte[] Gbytes = Base64.getDecoder().decode(Gstring);
            BigInteger G = new BigInteger(Gbytes);
            String GXstring = pIn.readLine(); 
            byte[] GXbytes = Base64.getDecoder().decode(GXstring);
            BigInteger GX = new BigInteger(GXbytes);
            System.out.println("Respuesta del Servidor: " + P);
            System.out.println("Respuesta del Servidor: " + G);
            System.out.println("Respuesta del Servidor: " + GX);



            fromUser = null;
            fromUser = stdIn.readLine();

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

