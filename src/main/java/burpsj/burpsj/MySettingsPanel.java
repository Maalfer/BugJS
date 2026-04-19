package burpsj.burpsj;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.awt.Desktop;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.regex.*;

public class MySettingsPanel extends JPanel {
    private JTextField pathField;
    private JTextField filterField;
    private JTextField searchField;
    private JTable filesTable;
    private JTable secretsTable;
    private JTable endpointsTable;
    private DefaultTableModel filesModel;
    private DefaultTableModel secretsModel;
    private DefaultTableModel endpointsModel;
    private JLabel statusLabel;
    private Set<String> filterWords;
    private MontoyaApi api;
    private JToggleButton toggleBtn;
    private JToggleButton autoDetectBtn;
    private JToggleButton sourceMapBtn;
    private boolean savingEnabled = false;
    private boolean autoDetectEnabled = true;
    private boolean downloadSourceMaps = true;
    private JPanel filterTagsPanel;
    private JTabbedPane tabbedPane;
    private List<FileData> allFiles = new ArrayList<>();
    private JButton exportBtn;
    private JButton sendToRepeaterBtn;
    
    private static class FileData {
        String fileName;
        String url;
        String content;
        long size;
        String matches;
        List<SecretDetector.Finding> findings;
        List<String> endpoints;
        String filterMatches; // Coincidencias de filtros personalizados
        
        FileData(String fileName, String url, String content, long size, String matches,
                 List<SecretDetector.Finding> findings, List<String> endpoints, String filterMatches) {
            this.fileName = fileName;
            this.url = url;
            this.content = content;
            this.size = size;
            this.matches = matches;
            this.findings = findings;
            this.endpoints = endpoints;
            this.filterMatches = filterMatches;
        }
    }

    public MySettingsPanel() {
        setLayout(new BorderLayout(5, 5));
        filterWords = new HashSet<>();

        // Panel superior: Configuración
        JPanel topPanel = createTopPanel();
        add(topPanel, BorderLayout.NORTH);
        
        // Panel central: Tabs con archivos, secretos, endpoints y filtros
        tabbedPane = new JTabbedPane();
        
        // Tab 1: Archivos JS
        filesModel = new DefaultTableModel(new String[]{"Archivo", "URL", "Tamaño", "Secretos", "Severidad"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        filesTable = new JTable(filesModel);
        filesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        filesTable.setDefaultRenderer(Object.class, new SeverityRenderer());
        filesTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        filesTable.getColumnModel().getColumn(1).setPreferredWidth(400);
        filesTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        filesTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        filesTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        
        // Menú contextual y doble clic
        setupFilesTableContextMenu();
        filesTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && filesTable.getSelectedRow() >= 0) {
                    openFileAtRow(filesTable.getSelectedRow());
                }
            }
        });
        
        // Panel de búsqueda
        JPanel searchPanel = new JPanel(new BorderLayout(5, 0));
        searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        searchPanel.add(new JLabel("Buscar:"), BorderLayout.WEST);
        searchField = new JTextField();
        searchField.setToolTipText("Filtrar archivos por nombre o contenido");
        searchField.addActionListener(e -> filterFiles());
        searchPanel.add(searchField, BorderLayout.CENTER);
        JButton searchBtn = new JButton("🔍");
        searchBtn.addActionListener(e -> filterFiles());
        searchPanel.add(searchBtn, BorderLayout.EAST);
        
        JPanel filesPanel = new JPanel(new BorderLayout());
        filesPanel.add(searchPanel, BorderLayout.NORTH);
        filesPanel.add(new JScrollPane(filesTable), BorderLayout.CENTER);
        tabbedPane.addTab("Archivos JS", filesPanel);
        
        // Tab 3: Secretos detectados
        secretsModel = new DefaultTableModel(new String[]{"Severidad", "Tipo", "Archivo", "Línea", "Vista previa"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        secretsTable = new JTable(secretsModel);
        // Sin renderer personalizado - usar default del tema
        secretsTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        
        // Doble clic para abrir el archivo JS correspondiente
        secretsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && secretsTable.getSelectedRow() >= 0) {
                    int row = secretsTable.getSelectedRow();
                    String fileName = (String) secretsModel.getValueAt(row, 2); // Columna "Archivo"
                    openFileByName(fileName);
                }
            }
        });
        secretsTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        secretsTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        secretsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        secretsTable.getColumnModel().getColumn(4).setPreferredWidth(300);
        tabbedPane.addTab("🔴 Secretos", new JScrollPane(secretsTable));
        
        // Tab 4: Endpoints
        endpointsModel = new DefaultTableModel(new String[]{"Endpoint", "Archivo fuente"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        endpointsTable = new JTable(endpointsModel);
        endpointsTable.getColumnModel().getColumn(0).setPreferredWidth(500);
        endpointsTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        
        sendToRepeaterBtn = new JButton("Enviar a Repeater");
        sendToRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        
        JPanel endpointsPanel = new JPanel(new BorderLayout());
        endpointsPanel.add(new JScrollPane(endpointsTable), BorderLayout.CENTER);
        JPanel endpointsBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        endpointsBtnPanel.add(sendToRepeaterBtn);
        endpointsPanel.add(endpointsBtnPanel, BorderLayout.SOUTH);
        tabbedPane.addTab("🌐 Endpoints", endpointsPanel);
        
        // Tab 5: Filtros (al final)
        filterTagsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        filterTagsPanel.setOpaque(false);
        JScrollPane filterScroll = new JScrollPane(filterTagsPanel);
        filterScroll.setBorder(BorderFactory.createTitledBorder("Filtros activos (clic en × para eliminar)"));
        tabbedPane.addTab("🔍 Filtros", filterScroll);
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Panel inferior: Botones y estado
        JPanel bottomPanel = new JPanel(new BorderLayout());
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        exportBtn = new JButton("📊 Exportar Reporte");
        exportBtn.addActionListener(e -> exportReport());
        buttonPanel.add(exportBtn);
        
        JButton clearBtn = new JButton("🗑️ Limpiar todo");
        clearBtn.addActionListener(e -> clearAllFiles());
        buttonPanel.add(clearBtn);
        
        bottomPanel.add(buttonPanel, BorderLayout.WEST);
        
        statusLabel = new JLabel("Listo. bugjs cargado. Configure la carpeta de destino.");
        bottomPanel.add(statusLabel, BorderLayout.CENTER);
        
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 3, 3, 3);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Fila 0: Carpeta destino
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("📁 Carpeta:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        pathField = new JTextField(35);
        panel.add(pathField, gbc);
        
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        JButton browseButton = new JButton("Seleccionar...");
        browseButton.addActionListener(e -> selectFolder());
        panel.add(browseButton, gbc);
        
        // Fila 1: Filtros
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("🔍 Filtros:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        filterField = new JTextField(35);
        filterField.setToolTipText("Separar con comas: token, api, password...");
        panel.add(filterField, gbc);
        
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE;
        JButton addFilterBtn = new JButton("➕ Añadir");
        addFilterBtn.addActionListener(e -> addFilterFromField());
        panel.add(addFilterBtn, gbc);
        
        // Fila 2: Controles
        gbc.gridx = 0; gbc.gridy = 2;
        toggleBtn = new JToggleButton("⏸️ Captura: OFF", false);
        toggleBtn.setToolTipText("Habilitar/deshabilitar la captura automática de archivos JS");
        toggleBtn.setBackground(new Color(120, 120, 120));
        toggleBtn.setForeground(Color.WHITE);
        toggleBtn.setFocusPainted(false);
        toggleBtn.addActionListener(e -> toggleSaving());
        panel.add(toggleBtn, gbc);
        
        gbc.gridx = 1;
        autoDetectBtn = new JToggleButton("🔮 Auto-detectar: ON", true);
        autoDetectBtn.setToolTipText("Detectar automáticamente secretos con regex");
        autoDetectBtn.addActionListener(e -> toggleAutoDetect());
        panel.add(autoDetectBtn, gbc);
        
        gbc.gridx = 2;
        sourceMapBtn = new JToggleButton("🗺️ Source Maps: ON", true);
        sourceMapBtn.setToolTipText("Descargar archivos .js.map cuando estén disponibles");
        sourceMapBtn.addActionListener(e -> toggleSourceMaps());
        panel.add(sourceMapBtn, gbc);
        
        return panel;
    }
    
    private void setupFilesTableContextMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem openItem = new JMenuItem("Abrir archivo");
        openItem.addActionListener(e -> {
            int row = filesTable.getSelectedRow();
            if (row >= 0) openFileAtRow(row);
        });
        popup.add(openItem);
        popup.addSeparator();
        JMenuItem clearItem = new JMenuItem("Limpiar todos los archivos");
        clearItem.addActionListener(e -> clearAllFiles());
        popup.add(clearItem);
        filesTable.setComponentPopupMenu(popup);
    }

    private void selectFolder() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            pathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }


    private void toggleSaving() {
        savingEnabled = toggleBtn.isSelected();
        toggleBtn.setText(savingEnabled ? "▶️ Captura: ON" : "⏸️ Captura: OFF");
        toggleBtn.setBackground(savingEnabled ? new Color(76, 175, 80) : new Color(120, 120, 120));
        if (api != null) {
            api.logging().logToOutput("[CAPTURA] " + (savingEnabled ? "Habilitada" : "Deshabilitada"));
        }
    }

    private void toggleAutoDetect() {
        autoDetectEnabled = autoDetectBtn.isSelected();
        autoDetectBtn.setText(autoDetectEnabled ? "🔮 Auto-detectar: ON" : "🔮 Auto-detectar: OFF");
    }

    private void toggleSourceMaps() {
        downloadSourceMaps = sourceMapBtn.isSelected();
        sourceMapBtn.setText(downloadSourceMaps ? "🗺️ Source Maps: ON" : "🗺️ Source Maps: OFF");
    }

    public boolean isSavingEnabled() { return savingEnabled; }
    public boolean isAutoDetectEnabled() { return autoDetectEnabled; }
    public boolean isSourceMapsEnabled() { return downloadSourceMaps; }

    private void addFilterFromField() {
        String text = filterField.getText().trim();
        if (text.isEmpty()) return;
        String[] words = text.split(",");
        for (String word : words) {
            String trimmed = word.trim().toLowerCase();
            if (!trimmed.isEmpty() && !filterWords.contains(trimmed)) {
                filterWords.add(trimmed);
                addFilterTag(trimmed);
            }
        }
        filterField.setText("");
        statusLabel.setText("Filtros: " + filterWords.size());
    }

    private void addFilterTag(String word) {
        JPanel tagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        tagPanel.setOpaque(true);
        tagPanel.setBackground(new Color(30, 136, 229));
        tagPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(21, 101, 192), 1, true),
            BorderFactory.createEmptyBorder(4, 10, 4, 8)
        ));
        
        JLabel wordLabel = new JLabel(word);
        wordLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        wordLabel.setForeground(Color.WHITE);
        
        JButton removeBtn = new JButton("×");
        removeBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        removeBtn.setForeground(new Color(255, 200, 200));
        removeBtn.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0));
        removeBtn.setContentAreaFilled(false);
        removeBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        removeBtn.setToolTipText("Eliminar: " + word);
        removeBtn.addActionListener(e -> removeFilter(word, tagPanel));
        
        tagPanel.add(wordLabel);
        tagPanel.add(removeBtn);
        filterTagsPanel.add(tagPanel);
        filterTagsPanel.revalidate();
        filterTagsPanel.repaint();
    }

    private void removeFilter(String word, JPanel tagPanel) {
        filterWords.remove(word);
        filterTagsPanel.remove(tagPanel);
        filterTagsPanel.revalidate();
        filterTagsPanel.repaint();
        statusLabel.setText("Filtros: " + filterWords.size());
    }

    private void clearAllFilters() {
        filterWords.clear();
        filterTagsPanel.removeAll();
        filterTagsPanel.revalidate();
        filterTagsPanel.repaint();
        statusLabel.setText("Filtros: Ninguno");
    }

    public void addFileEntry(String fileName, String url, String content, long size, 
                             List<SecretDetector.Finding> findings, List<String> endpoints, String filterMatches) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < filesModel.getRowCount(); i++) {
                if (filesModel.getValueAt(i, 1).equals(url)) return;
            }
            String severity = findings.isEmpty() ? "-" : findings.get(0).severity.toString();
            int criticalCount = 0;
            for (SecretDetector.Finding f : findings) {
                if (f.severity == SecretDetector.Severity.CRITICAL) criticalCount++;
            }
            String findingSummary = findings.isEmpty() ? "-" : 
                (criticalCount > 0 ? "🔴 " + criticalCount : String.valueOf(findings.size()));
            String secretsColumn;
            if (criticalCount > 0) {
                secretsColumn = "🔴 " + criticalCount + " secretos";
            } else if (!findings.isEmpty()) {
                secretsColumn = String.valueOf(findings.size());
            } else if (filterMatches != null && !filterMatches.isEmpty()) {
                secretsColumn = "🔴 Filtro: " + (filterMatches.length() > 20 ? filterMatches.substring(0, 20) + "..." : filterMatches);
            } else {
                secretsColumn = "-";
            }
            FileData data = new FileData(fileName, url, content, size, "", findings, endpoints, filterMatches);
            allFiles.add(data);
            filesModel.addRow(new Object[]{fileName, url, size + " B", secretsColumn, severity});
            for (SecretDetector.Finding f : findings) {
                String preview = f.value.length() > 40 ? f.value.substring(0, 40) + "..." : f.value;
                secretsModel.addRow(new Object[]{
                    SecretDetector.getSeverityIcon(f.severity) + " " + f.severity,
                    f.type, fileName, f.lineNumber, preview
                });
            }
            for (String ep : endpoints) {
                endpointsModel.addRow(new Object[]{ep, fileName});
            }
            statusLabel.setText("Archivos: " + allFiles.size() + " | Secretos: " + secretsModel.getRowCount() + 
                              " | Endpoints: " + endpointsModel.getRowCount());
            if (!findings.isEmpty() && api != null) {
                api.logging().logToOutput("[SECRETO] " + fileName + " - " + findings.get(0).type);
            } else if (filterMatches != null && !filterMatches.isEmpty() && api != null) {
                api.logging().logToOutput("[FILTRO] " + fileName + " - Coincidencias: " + filterMatches);
            }
        });
    }

    private void filterFiles() {
        String search = searchField.getText().toLowerCase().trim();
        filesModel.setRowCount(0);
        for (FileData data : allFiles) {
            if (search.isEmpty() || 
                data.fileName.toLowerCase().contains(search) ||
                data.url.toLowerCase().contains(search) ||
                data.content.toLowerCase().contains(search)) {
                int criticalCount = 0;
                for (SecretDetector.Finding f : data.findings) {
                    if (f.severity == SecretDetector.Severity.CRITICAL) criticalCount++;
                }
                String findingSummary = data.findings.isEmpty() ? "-" : 
                    (criticalCount > 0 ? "🔴 " + criticalCount : String.valueOf(data.findings.size()));
                String severity = data.findings.isEmpty() ? "-" : data.findings.get(0).severity.toString();
                filesModel.addRow(new Object[]{data.fileName, data.url, data.size + " B", findingSummary, severity});
            }
        }
    }

    private void exportReport() {
        if (allFiles.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No hay archivos para exportar", "Aviso", JOptionPane.WARNING_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("bugjs_report_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        
        StringBuilder json = new StringBuilder();
        json.append("{\n  \"generatedAt\": \"").append(new Date().toString()).append("\",\n");
        json.append("  \"summary\": {\n    \"totalFiles\": ").append(allFiles.size()).append(",\n");
        json.append("    \"totalSecrets\": ").append(secretsModel.getRowCount()).append(",\n");
        json.append("    \"totalEndpoints\": ").append(endpointsModel.getRowCount()).append("\n  },\n  \"files\": [\n");
        
        for (int i = 0; i < allFiles.size(); i++) {
            FileData d = allFiles.get(i);
            json.append("    {\n      \"file\": \"").append(escapeJson(d.fileName)).append("\",\n");
            json.append("      \"url\": \"").append(escapeJson(d.url)).append("\",\n");
            json.append("      \"size\": ").append(d.size).append(",\n      \"findings\": [\n");
            for (int j = 0; j < d.findings.size(); j++) {
                SecretDetector.Finding f = d.findings.get(j);
                json.append("        {\"type\": \"").append(escapeJson(f.type)).append("\", ");
                json.append("\"severity\": \"").append(f.severity).append("\", ");
                json.append("\"line\": ").append(f.lineNumber).append("}");
                json.append(j < d.findings.size() - 1 ? ",\n" : "\n");
            }
            json.append("      ],\n      \"endpoints\": [");
            for (int j = 0; j < d.endpoints.size(); j++) {
                json.append("\"").append(escapeJson(d.endpoints.get(j))).append("\"");
                if (j < d.endpoints.size() - 1) json.append(", ");
            }
            json.append("]\n    }").append(i < allFiles.size() - 1 ? "," : "").append("\n");
        }
        json.append("  ]\n}");
        
        try {
            Files.write(chooser.getSelectedFile().toPath(), json.toString().getBytes(StandardCharsets.UTF_8));
            statusLabel.setText("Reporte exportado: " + chooser.getSelectedFile().getName());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void sendSelectedToRepeater() {
        int row = endpointsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Selecciona un endpoint");
            return;
        }
        if (api == null) {
            JOptionPane.showMessageDialog(this, "API no disponible");
            return;
        }
        
        String endpoint = (String) endpointsModel.getValueAt(row, 0);
        String fileName = (String) endpointsModel.getValueAt(row, 1);
        
        // Encontrar URL base del archivo
        String baseUrl = "";
        for (FileData d : allFiles) {
            if (d.fileName.equals(fileName)) { 
                baseUrl = d.url; 
                break; 
            }
        }
        
        // Construir URL completa
        String fullUrl;
        if (endpoint.startsWith("http")) {
            fullUrl = endpoint;
        } else {
            // Extraer base de la URL (protocolo + dominio)
            int thirdSlash = baseUrl.indexOf('/', baseUrl.indexOf("//") + 2);
            String base = (thirdSlash > 0) ? baseUrl.substring(0, thirdSlash) : baseUrl;
            fullUrl = base + (endpoint.startsWith("/") ? "" : "/") + endpoint;
        }
        
        try {
            // Usar el método HTTP del Burp para enviar al Repeater
            api.repeater().sendToRepeater(
                burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(fullUrl)
            );
            statusLabel.setText("Enviado a Repeater: " + fullUrl);
            
        } catch (Exception e) {
            // Fallback: copiar al portapapeles si falla
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(fullUrl);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            statusLabel.setText("URL copiada (error Repeater): " + fullUrl);
            JOptionPane.showMessageDialog(this, "No se pudo enviar a Repeater. URL copiada:\n" + fullUrl + "\nError: " + e.getMessage());
        }
    }

    private void openFileAtRow(int row) {
        String folderPath = getSavePath();
        if (folderPath.isEmpty()) return;
        String fileName = (String) filesModel.getValueAt(row, 0);
        openFileByName(fileName);
    }
    
    private void openFileByName(String fileName) {
        String folderPath = getSavePath();
        if (folderPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No hay carpeta de destino configurada", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        File file = new File(folderPath, fileName);
        if (!file.exists()) { 
            JOptionPane.showMessageDialog(this, "Archivo no encontrado: " + fileName, "Error", JOptionPane.ERROR_MESSAGE); 
            return; 
        }
        try { 
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(file);
                statusLabel.setText("Abierto: " + fileName);
            }
        }
        catch (IOException e) { 
            JOptionPane.showMessageDialog(this, "Error al abrir: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE); 
        }
    }

    private void clearAllFiles() {
        String folderPath = getSavePath();
        int confirm = JOptionPane.showConfirmDialog(this, "¿Eliminar todos los archivos?", "Confirmar", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;
        int deleted = 0;
        for (FileData d : allFiles) {
            File f = new File(folderPath, d.fileName);
            if (f.exists() && f.delete()) deleted++;
        }
        allFiles.clear();
        filesModel.setRowCount(0);
        secretsModel.setRowCount(0);
        endpointsModel.setRowCount(0);
        statusLabel.setText("Eliminados: " + deleted + " archivos");
    }

    public String getSavePath() { return pathField.getText(); }
    public Set<String> getFilterWords() { return new HashSet<>(filterWords); }
    public void setApi(MontoyaApi api) { this.api = api; }

    private class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            Component comp = super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            // Sin colores personalizados - usar siempre los del tema de Burp Suite
            return comp;
        }
    }
}
