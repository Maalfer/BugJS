package burpsj.burpsj;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.GZIPInputStream;

public class JsHandler implements HttpHandler {
    private final MontoyaApi api;
    private final MySettingsPanel settings;

    public JsHandler(MontoyaApi api, MySettingsPanel settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        String url = response.initiatingRequest().url();
        
        // Descargar source maps si está habilitado
        if (settings.isSourceMapsEnabled() && (url.toLowerCase().endsWith(".js") || isJsContentType(response))) {
            String sourceMapUrl = url + ".map";
            api.logging().logToOutput("[SOURCEMAP] Intentando: " + sourceMapUrl);
        }
        
        // Verificar si la captura está habilitada
        if (!settings.isSavingEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }
        
        // Verificar si la URL termina en .js o el Content-Type es javascript
        if (url.toLowerCase().endsWith(".js") || isJsContentType(response)) {
            byte[] bodyBytes = response.body().getBytes();
            
            // Verificar si está comprimido con gzip
            if (isGzipped(response)) {
                bodyBytes = decompressGzip(bodyBytes);
            }
            
            // Convertir a String para análisis
            String content = new String(bodyBytes, StandardCharsets.UTF_8);
            
            // Analizar secretos si está habilitado
            List<SecretDetector.Finding> findings = settings.isAutoDetectEnabled() ? 
                SecretDetector.analyze(content) : java.util.Collections.emptyList();
            
            // Verificar filtros personalizados
            String filterMatches = checkFilterMatches(content, settings.getFilterWords());
            
            // Extraer endpoints
            List<String> endpoints = SecretDetector.extractEndpoints(content);
            
            saveJsFile(url, content, bodyBytes.length, findings, endpoints, filterMatches);
        }
        
        return ResponseReceivedAction.continueWith(response);
    }

    private boolean isJsContentType(HttpResponse response) {
        String contentType = response.headerValue("Content-Type");
        return contentType != null && 
               (contentType.contains("javascript") || contentType.contains("js"));
    }

    private boolean isGzipped(HttpResponse response) {
        String encoding = response.headerValue("Content-Encoding");
        return encoding != null && encoding.toLowerCase().contains("gzip");
    }

    private byte[] decompressGzip(byte[] compressed) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
             GZIPInputStream gis = new GZIPInputStream(bis)) {
            return gis.readAllBytes();
        } catch (IOException e) {
            api.logging().logToError("Error al descomprimir gzip: " + e.getMessage());
            return compressed;
        }
    }

    private String checkFilterMatches(String content, java.util.Set<String> filterWords) {
        if (filterWords == null || filterWords.isEmpty() || content == null) {
            return "";
        }
        String lowerContent = content.toLowerCase();
        StringBuilder matches = new StringBuilder();
        for (String word : filterWords) {
            if (lowerContent.contains(word.toLowerCase())) {
                if (matches.length() > 0) matches.append(", ");
                matches.append(word);
            }
        }
        return matches.toString();
    }

    private void saveJsFile(String url, String content, int originalSize, 
                              List<SecretDetector.Finding> findings, List<String> endpoints, String filterMatches) {
        String folderPath = settings.getSavePath();
        if (folderPath.isEmpty()) return;

        try {
            // Extraer solo el nombre del archivo de la URL
            String fileName = extractFileName(url);
            
            // Si el archivo ya termina en .js, no añadir otra extensión
            if (!fileName.toLowerCase().endsWith(".js")) {
                fileName += ".js";
            }
            
            // Evitar nombres duplicados añadiendo un contador si es necesario
            Path path = getUniquePath(folderPath, fileName);
            
            // Guardar el archivo
            Files.write(path, content.getBytes(StandardCharsets.UTF_8));
            
            // Añadir entrada a la tabla con findings, endpoints y filterMatches
            settings.addFileEntry(path.getFileName().toString(), url, content, content.length(), findings, endpoints, filterMatches);
            
            if (!findings.isEmpty()) {
                api.logging().logToOutput("[SECRETO] " + path.getFileName() + " - " + findings.get(0).type);
            } else if (!filterMatches.isEmpty()) {
                api.logging().logToOutput("[FILTRO] " + path.getFileName() + " - Coincidencias: " + filterMatches);
            } else {
                api.logging().logToOutput("[bugjs] Guardado: " + path.getFileName());
            }
        } catch (Exception e) {
            api.logging().logToError("[bugjs] Error al guardar: " + e.getMessage());
        }
    }

    private String extractFileName(String url) {
        try {
            URL u = new URL(url);
            String path = u.getPath();
            
            // Quitar parámetros de query si los hay
            if (path.contains("?")) {
                path = path.substring(0, path.indexOf("?"));
            }
            
            // Obtener solo el nombre del archivo (última parte del path)
            if (path.contains("/")) {
                path = path.substring(path.lastIndexOf("/") + 1);
            }
            
            // Si queda vacío o no tiene .js, usar un nombre basado en el host
            if (path.isEmpty() || !path.contains(".")) {
                String host = u.getHost().replaceAll("[^a-zA-Z0-9.-]", "_");
                path = host + (path.isEmpty() ? "_script.js" : "_" + path + ".js");
            }
            
            // Limpiar caracteres no válidos para nombres de archivo
            path = path.replaceAll("[^a-zA-Z0-9.-]", "_");
            
            return path;
        } catch (Exception e) {
            // Fallback: limpiar la URL completa
            return url.replaceAll("[^a-zA-Z0-9.-]", "_");
        }
    }

    private Path getUniquePath(String folderPath, String fileName) {
        Path path = Paths.get(folderPath, fileName);
        if (!Files.exists(path)) {
            return path;
        }
        
        // Si existe, añadir un contador
        int counter = 1;
        String baseName = fileName;
        String extension = "";
        
        if (fileName.contains(".")) {
            int lastDot = fileName.lastIndexOf(".");
            baseName = fileName.substring(0, lastDot);
            extension = fileName.substring(lastDot);
        }
        
        while (Files.exists(path)) {
            String newName = baseName + "_" + counter + extension;
            path = Paths.get(folderPath, newName);
            counter++;
        }
        
        return path;
    }
}