package burpsj.burpsj;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class JsSaver implements BurpExtension {
    private MontoyaApi api;
    private MySettingsPanel settingsPanel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("BugJS");

        // 1. Crear el panel de configuración
        settingsPanel = new MySettingsPanel();
        settingsPanel.setApi(api); // Pasar API para habilitar escaneo de historial

        // 2. Registrar la pestaña en la interfaz de Burp
        api.userInterface().registerSuiteTab("BugJS", settingsPanel);

        // 3. Registrar el manejador de tráfico HTTP
        api.http().registerHttpHandler(new JsHandler(api, settingsPanel));

        api.logging().logToOutput("BugJS cargado. Estado: OFF (Captura deshabilitada)");
        api.logging().logToOutput("Activa el toggle 'Captura' para comenzar a interceptar archivos JS.");
    }
}