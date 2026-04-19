# BugJS - AI Assistant Context

## TL;DR
Burp Suite extension for Bug Bounty. Captures JS files, detects 50+ secret patterns (API keys, tokens), extracts endpoints, exports JSON reports.

## Architecture
```
src/main/java/burpsj/burpsj/
├── JsSaver.java          # Entry point, registers extension
├── JsHandler.java        # HTTP handler, intercepts JS responses
├── MySettingsPanel.java  # UI (Swing), 4 tabs, manages state
└── SecretDetector.java   # 50+ regex patterns, severity classification
```

## Key Files & Responsibilities

### JsSaver.java
- Extension name: "BugJS"
- Tab name: "BugJS"
- Registers: MySettingsPanel (UI), JsHandler (HTTP traffic)
- Default state: Captura=OFF (disabled by default)

### JsHandler.java
- Intercepts .js files and JS Content-Type responses
- Handles gzip decompression
- Calls SecretDetector.analyze() for auto-detection
- Calls SecretDetector.extractEndpoints() for API discovery
- Saves files to configured folder

### MySettingsPanel.java
**UI Layout:**
- North: Config panel (folder, filters, toggles)
- Center: JTabbedPane with 4 tabs:
  1. 📁 Archivos JS - Table with files, double-click opens file
  2. 🔴 Secretos - Table with secrets, double-click opens source file
  3. 🌐 Endpoints - API endpoints found, "Enviar a Repeater" button
  4. 🔍 Filtros - Custom filter words, blue tags with X to remove
- South: Export button, Clear button, status label

**State:**
- savingEnabled = false (default OFF)
- autoDetectEnabled = true
- downloadSourceMaps = true

**Important Methods:**
- addFileEntry() - Called from JsHandler, adds to all tables
- sendSelectedToRepeater() - Sends selected endpoint to Burp Repeater
- openFileByName() - Opens JS file with system default editor
- exportReport() - Exports JSON with all findings

### SecretDetector.java
**Severity Levels:**
- CRITICAL: API keys, tokens, passwords, private keys (50+ patterns)
- MEDIUM: Endpoints, admin URLs, internal URLs
- LOW: Emails, IPs, UUIDs
- INFO: TODO/FIXME comments, versions

**Key Patterns (CRITICAL):**
- AWS: AKIA..., SK..., AC...
- Google: AIza..., ya29..., service_account
- Stripe: sk_live..., pk_live...
- GitHub: ghp_..., github_pat_..., gho_...
- Slack: xoxb..., hooks.slack.com
- Discord: webhook URLs, bot tokens
- JWT: eyJ...eyJ... format
- DB: mongodb://, postgres://, redis://
- Generic: password=, secret=, api_key= patterns
- Private keys: -----BEGIN... headers

**Methods:**
- analyze(content) → List<Finding> with type, value, severity, line number
- extractEndpoints(content) → List<String> of URLs/paths

## Data Flow
1. Burp HTTP traffic → JsHandler.handleHttpResponseReceived()
2. Check if JS file → decompress gzip → string content
3. If autoDetect: findings = SecretDetector.analyze(content)
4. endpoints = SecretDetector.extractEndpoints(content)
5. filterMatches = check against user filter words
6. save to disk
7. SwingUtilities.invokeLater() → settingsPanel.addFileEntry()
8. Updates: filesTable, secretsTable, endpointsTable, statusLabel

## UI Tables
**filesModel:** [Archivo, URL, Tamaño, Secretos, Severidad]
- Secretos column shows 🔴 if critical findings or filter matches
- Severity shows CRITICAL/MEDIUM/LOW/INFO or -

**secretsModel:** [Severidad, Tipo, Archivo, Línea, Vista previa]
- Double-click opens the source JS file
- Icon prefix: 🔴🟡🔵⚪ based on severity

**endpointsModel:** [Endpoint, Archivo fuente]
- "Enviar a Repeater" button sends to Burp Repeater

## Critical Implementation Notes

### Thread Safety
- All UI updates must use SwingUtilities.invokeLater()
- JsHandler runs on Burp's HTTP handler thread
- MySettingsPanel methods check Swing thread

### File Storage
- Files saved to: getSavePath() + extracted filename
- Duplicate handling: adds counter (_1, _2) to filename
- Content saved as UTF-8

### Repeater Integration
```java
api.repeater().sendToRepeater(
    HttpRequest.httpRequestFromUrl(fullUrl)
);
```

### Color/Theme Handling
- NO custom colors in tables (removed SeverityRenderer colors)
- Uses Burp Suite's default theme colors
- Filter tags: blue background (#1E88E5), white text

## Build & Deploy

### Maven
```bash
mvn clean package -DskipTests
# Output: target/bugjs-1.0.0-jar-with-dependencies.jar
```

### GitHub Actions
- `.github/workflows/build.yml` - CI on every push
- `.github/workflows/release.yml` - Auto-release on push to main
- Creates release: build-N-SHA with JAR attached

### Installation
Burp → Extensions → Installed → Add → Java → Select JAR

## Common Modification Patterns

### Adding new secret pattern
1. Edit SecretDetector.java
2. Add new PatternConfig to PATTERNS list
3. Choose severity: CRITICAL/MEDIUM/LOW/INFO
4. Test regex, compile, done

### Adding new UI element
1. MySettingsPanel constructor
2. Add to createTopPanel() for controls
3. Or add new tab to tabbedPane
4. Update layout with GridBagConstraints
5. Action listeners update state variables

### Modifying table columns
- filesModel: line ~88
- secretsModel: line ~129
- endpointsModel: line ~154
- Adjust column widths with setPreferredWidth()

## Anti-Patterns (DON'T)
- DON'T use colored backgrounds in tables (breaks dark themes)
- DON'T update UI from HTTP handler thread (use invokeLater)
- DON'T forget to check api != null before logging
- DON'T make synchronous HTTP calls from UI thread
- DON'T use hardcoded paths (use getSavePath())

## Testing Checklist
- [ ] Extension loads in Burp without errors
- [ ] Toggle ON/OFF works, captures when ON only
- [ ] JS files saved to configured folder
- [ ] Secretos tab populates when auto-detect ON
- [ ] Endpoints tab populates
- [ ] Doble-click opens files
- [ ] Export JSON works
- [ ] Enviar a Repeater works
- [ ] Filter tags add/remove correctly
- [ ] Clear all removes files from disk

## Quick Commands
```bash
# Build
mvn clean package -DskipTests

# Run (manual install in Burp)
# JAR at: target/bugjs-1.0.0-jar-with-dependencies.jar

# Git workflow
git add .
git commit -m "Description"
git push origin main  # Triggers Actions build
```

## Dependencies
- Java 17+
- Maven 3.6+
- Burp Suite (any edition with Montoya API)
- montoya-api:2023.12.1 (in pom.xml)

## Project Structure
```
burpsj/
├── src/main/java/burpsj/burpsj/  # Source code
├── .github/workflows/             # CI/CD
├── media/                         # Screenshots
├── pom.xml                        # Maven config
├── README.md                      # Documentation
├── .gitignore                     # Excludes target/, IDE files
└── agent.md                       # This file
```

## When Making Changes
1. Prefer minimal edits - single line changes when possible
2. Test compilation: `mvn clean package -DskipTests`
3. Maintain backwards compatibility if possible
4. Don't break existing UI layout (GridBagConstraints are fragile)
5. Keep Swing thread safety - use invokeLater for UI updates
6. Log important events via api.logging().logToOutput()

## Extension State Summary
- **Name:** BugJS
- **Default:** OFF (user must enable Captura toggle)
- **Auto-detect:** ON by default (50+ patterns)
- **Source Maps:** ON by default (attempts .js.map download)
- **Theme:** Follows Burp Suite theme (no custom colors)
