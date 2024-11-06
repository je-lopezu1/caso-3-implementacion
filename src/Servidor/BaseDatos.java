package Servidor;

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class BaseDatos {

    private final Map<String, Map<String, Integer>> datos;

    public BaseDatos() {
        datos = new HashMap<>();
        inicializarDatos();
        imprimirValores();
    }

    // Método para inicializar el mapa con valores de ejemplo
    private void inicializarDatos() {
        Random random = new Random();
        int[] estados = {10, 11, 12, 13, 14, 15}; // Posibles estados

        for (int i = 1; i <= 10; i++) { // 10 usuarios
            String usuarioId = "u" + i;
            Map<String, Integer> paquetes = new HashMap<>();

            for (int j = 1; j <= 3; j++) { // Cada usuario tiene 3 paquetes
                String paqueteId = "p" + j;
                int estado = estados[random.nextInt(estados.length)];
                paquetes.put(paqueteId, estado);
            }

            datos.put(usuarioId, paquetes);
        }
    }

    // Método para obtener el estado del paquete
    public String obtenerEstadoPaquete(String usuarioId, String paqueteId) {
        Map<String, Integer> paquetesUsuario = datos.get(usuarioId);

        if (paquetesUsuario != null) {
            Integer estado = paquetesUsuario.get(paqueteId);
            if (estado != null) {
                return estado.toString();
            }
        }
        return "16"; // Retornar 16 si el usuario o el paquete no existe
    }

    // Método para imprimir todos los valores del mapa y guardarlos en un archivo
    public void imprimirValores() {
        try (FileWriter writer = new FileWriter("src/Servidor/valoresBaseDatos.txt")) {
            for (Map.Entry<String, Map<String, Integer>> entryUsuario : datos.entrySet()) {
                String usuarioId = entryUsuario.getKey();
                Map<String, Integer> paquetes = entryUsuario.getValue();

                for (Map.Entry<String, Integer> entryPaquete : paquetes.entrySet()) {
                    String paqueteId = entryPaquete.getKey();
                    Integer estado = entryPaquete.getValue();

                    // Formato de impresión
                    String linea = "Usuario: " + usuarioId + ", Paquete: " + paqueteId + ", Estado: " + estado;
                    //System.out.println(linea);
                    writer.write(linea + "\n");
                }
            }
            System.out.println("Los valores se han guardado en valoresBaseDatos.txt.");
        } catch (IOException e) {
            System.err.println("Error al escribir en el archivo: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        BaseDatos baseDatos = new BaseDatos();
        //System.out.println("Estado del paquete p2 para el usuario u5: " + baseDatos.obtenerEstadoPaquete("u5", "p2"));

        // Imprimir y guardar todos los valores en el archivo
        baseDatos.imprimirValores();
    }
}

