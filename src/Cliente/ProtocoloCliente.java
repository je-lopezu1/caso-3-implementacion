package Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ProtocoloCliente {
    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publicKey) throws IOException, NoSuchAlgorithmException {
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
            String firmaString = pIn.readLine(); 
            byte[] firma = Base64.getDecoder().decode(firmaString);
            //byte[] firma = firmaString.getBytes();
            System.out.println("Respuesta del Servidor: Valor de P: " + P);
            System.out.println("Respuesta del Servidor: Valor de G: " + G);
            System.out.println("Respuesta del Servidor: Valor de G^x: " + GX);
            System.out.println("Respuesta del Servidor: Firma obtenida: " + firma);
            try {
                // Convertir los valores de G, P, y Gx a bytes y concatenarlos
                byte[] gBytes = G.toByteArray();
                byte[] pBytes = P.toByteArray();
                byte[] gxBytes = GX.toByteArray();
    
                // Concatenar todos los bytes en un solo arreglo
                byte[] dataToVerify = new byte[gBytes.length + pBytes.length + gxBytes.length];
                System.arraycopy(gBytes, 0, dataToVerify, 0, gBytes.length);
                System.arraycopy(pBytes, 0, dataToVerify, gBytes.length, pBytes.length);
                System.arraycopy(gxBytes, 0, dataToVerify, gBytes.length + pBytes.length, gxBytes.length);
    
                // Configurar el objeto Signature con SHA1withRSA y la llave pública
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initVerify(publicKey);
    
                // Actualizar el objeto Signature con los datos originales
                signature.update(dataToVerify);
                // Verificar la firma
                boolean verificacionFirma = signature.verify(firma);
                System.out.println(verificacionFirma);
                if (!verificacionFirma)
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
    
            } catch (Exception e) {
                System.err.println("Error al verificar la firma: " + e.getMessage());
                
            }

            //11a
            // Generar un valor aleatorio para y
            try {
            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(1024, random); // Genera un número de 1024 bits
            // Calcular G^y mod P
            BigInteger Gy = G.modPow(y, P);
            System.out.println("Valor de G^y: " + Gy);

            // Calcular (G^x)^y mod P para obtener la clave compartida
            BigInteger sharedSecret = GX.modPow(y, P);
            System.out.println("Clave compartida (G^x)^y mod P: " + sharedSecret);

            // Derivar K_AB1 y K_AB2 a partir de la clave compartida
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
            System.out.println("BYTES: " + sharedSecretBytes);
            // Calcular K_AB1 y K_AB2 usando SHA-512 y dividir en dos mitades
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(sharedSecretBytes);
            
            // Dividir el hash en dos partes para obtener K_AB1 y K_AB2
            byte[] K_AB1 = new byte[32];
            byte[] K_AB2 = new byte[32];
            System.arraycopy(hash, 0, K_AB1, 0, 32);
            System.arraycopy(hash, 32, K_AB2, 0, 32);
            String K_AB1st = Base64.getEncoder().encodeToString(K_AB1);
            String K_AB2st = Base64.getEncoder().encodeToString(K_AB2);
            System.out.println("K_AB1: " + K_AB1st);
            System.out.println("K_AB2: " + K_AB2st);


            //mandar G^y
            String GYstring = Base64.getEncoder().encodeToString(Gy.toByteArray());
            pOut.println(GYstring);
            }
            catch (Exception e) {
                System.err.println("Error en el proceso de creación de llaves simetricas: " + e.getMessage());
            }
            //recibir vector
            String ivString = pIn.readLine(); 
            System.out.println("iv: " + ivString);
            byte[] iv = Base64.getDecoder().decode(ivString);
            IvParameterSpec vectorIV = new IvParameterSpec(iv);
            System.out.println("iv: " + vectorIV);
            //Empezar consulta

            System.out.println("Ingrese el id del usuario: ");
            String idU = stdIn.readLine();
            System.out.println("Ingrese el id del paquete: ");
            String iPaquete = stdIn.readLine();
            //cifrarID(idU, null, null)


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

     // Método para cifrar el ID con la clave K_AB1
    public static String cifrarID(String Id, SecretKey K_AB1, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, K_AB1, ivSpec);
        byte[] encryptedId = cipher.doFinal(Base64.getDecoder().decode(Id));
        return Base64.getEncoder().encodeToString(encryptedId);
    }

    // Método para generar HMAC del ID con la clave K_AB2
    public static String generarHMAC(String Id, SecretKey K_AB2) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(K_AB2);
        byte[] hmacBytes = hmac.doFinal(Id.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

   
}

