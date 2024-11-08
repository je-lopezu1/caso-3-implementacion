package Servidor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public class ThreadServidor extends Thread {
    private Socket sktCliente = null;
    private int id; // Atributo para identificar el thread
    private PrivateKey privateKey;

    // Constructor que inicializa el socket y el id del thread
    public ThreadServidor(Socket pSocket, int pId, PrivateKey privateKey) {
        this.sktCliente = pSocket;
        this.id = pId;
        this.privateKey = privateKey;
    }

    // Método que se ejecuta cuando el thread inicia
    public void run() {
        System.out.println("Inicio de un nuevo thread: " + id);

        try {
            // Crear escritor para enviar datos al cliente
            PrintWriter escritor = new PrintWriter(sktCliente.getOutputStream(), true);
            
            // Crear lector para recibir datos del cliente
            BufferedReader lector = new BufferedReader(new InputStreamReader(sktCliente.getInputStream()));

            try {
                BaseDatos baseDatos = new BaseDatos();
                ProtocoloServidor.procesar(lector, escritor, privateKey, baseDatos);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            // Cerrar los flujos y el socket
            escritor.close();
            lector.close();
            sktCliente.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}