package burpsj.burpsj;

import java.util.*;
import java.util.regex.*;

public class SecretDetector {
    
    public enum Severity {
        CRITICAL, MEDIUM, LOW, INFO
    }
    
    public static class Finding {
        public final String type;
        public final String value;
        public final Severity severity;
        public final String description;
        public final int lineNumber;
        
        public Finding(String type, String value, Severity severity, String description, int lineNumber) {
            this.type = type;
            this.value = value;
            this.severity = severity;
            this.description = description;
            this.lineNumber = lineNumber;
        }
    }
    
    private static final List<PatternConfig> PATTERNS = Arrays.asList(
        // ============================================
        // CRITICAL - API Keys y Tokens (Alta prioridad)
        // ============================================
        
        // AWS
        new PatternConfig("AWS Access Key", "AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS Access Key ID"),
        new PatternConfig("AWS Secret Key", "['\"][0-9a-zA-Z/+]{40}['\"]", Severity.CRITICAL, "Posible AWS Secret Key"),
        new PatternConfig("AWS Session Token", "['\"]FwoGZXIvYXdzE[0-9a-zA-Z/+=]{100,}['\"]", Severity.CRITICAL, "AWS Session Token"),
        
        // Google
        new PatternConfig("Google API Key", "AIza[0-9A-Za-z_-]{35}", Severity.CRITICAL, "Google API Key"),
        new PatternConfig("Google OAuth Token", "ya29\\.[0-9A-Za-z_-]+", Severity.CRITICAL, "Google OAuth Token"),
        new PatternConfig("GCP Service Account", "['\"]type['\"]\\s*:\\s*['\"]service_account['\"]", Severity.CRITICAL, "GCP Service Account JSON"),
        
        // Stripe
        new PatternConfig("Stripe Live Key", "sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL, "Stripe Live Secret Key"),
        new PatternConfig("Stripe Test Key", "sk_test_[0-9a-zA-Z]{24,}", Severity.CRITICAL, "Stripe Test Secret Key"),
        new PatternConfig("Stripe Publishable", "pk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL, "Stripe Live Publishable Key"),
        
        // GitHub
        new PatternConfig("GitHub Token (classic)", "ghp_[0-9a-zA-Z]{36}", Severity.CRITICAL, "GitHub Personal Access Token"),
        new PatternConfig("GitHub Fine-Grained", "github_pat_[0-9a-zA-Z_]{22,}", Severity.CRITICAL, "GitHub Fine-Grained Token"),
        new PatternConfig("GitHub OAuth", "gho_[0-9a-zA-Z]{36}", Severity.CRITICAL, "GitHub OAuth Token"),
        new PatternConfig("GitHub App Token", "ghu_[0-9a-zA-Z]{36}", Severity.CRITICAL, "GitHub App User Token"),
        new PatternConfig("GitHub Refresh", "ghr_[0-9a-zA-Z]{36}", Severity.CRITICAL, "GitHub Refresh Token"),
        
        // Slack
        new PatternConfig("Slack Token", "xox[baprs]-[0-9a-zA-Z]{10,48}", Severity.CRITICAL, "Slack Token"),
        new PatternConfig("Slack Webhook", "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", Severity.CRITICAL, "Slack Webhook URL"),
        
        // Discord
        new PatternConfig("Discord Bot Token", "[MN][A-Za-z\\d]{23}\\.[A-Za-z\\d_-]{6}\\.[A-Za-z\\d_-]{27}", Severity.CRITICAL, "Discord Bot Token"),
        new PatternConfig("Discord Webhook", "https://discord(?:app)?\\.com/api/webhooks/[0-9]{17,20}/[0-9a-zA-Z_-]+", Severity.CRITICAL, "Discord Webhook URL"),
        
        // JWT & Auth
        new PatternConfig("JWT Token", "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*", Severity.CRITICAL, "JWT Token"),
        new PatternConfig("Bearer Token", "Bearer\\s+[a-zA-Z0-9_\\-\\.=]{20,}", Severity.CRITICAL, "Bearer Authentication Token"),
        new PatternConfig("Basic Auth", "Basic\\s+[a-zA-Z0-9_\\-\\.=]{10,}", Severity.CRITICAL, "Basic Authentication"),
        new PatternConfig("API Key Header", "[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy\\s]*:\\s*[a-zA-Z0-9_\\-]{16,}", Severity.CRITICAL, "API Key in Header"),
        
        // Keys & Secrets
        new PatternConfig("Private Key", "-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", Severity.CRITICAL, "Private Key"),
        new PatternConfig("SSH Key", "ssh-(rsa|dss|ed25519)\\s+[A-Za-z0-9+/]{100,}", Severity.CRITICAL, "SSH Public Key"),
        new PatternConfig("Generic API Key", "['\"]?(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-]{16,}['\"]", Severity.CRITICAL, "Generic API Key/Secret"),
        new PatternConfig("Secret Key", "['\"]?(?:secret[_-]?key|secretkey|client[_-]?secret)['\"]?\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", Severity.CRITICAL, "Secret Key"),
        new PatternConfig("Password", "['\"]?(?:password|passwd|pwd)['\"]?\\s*[:=]\\s*['\"][^'\"]{4,}['\"]", Severity.CRITICAL, "Hardcoded Password"),
        new PatternConfig("Auth Token", "['\"]?(?:auth[_-]?token|access[_-]?token|token)['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-]{20,}['\"]", Severity.CRITICAL, "Authentication Token"),
        
        // Database
        new PatternConfig("DB Connection String", "(mongodb|mysql|postgres|postgresql|redis|elasticsearch)://[^\\s\"']+", Severity.CRITICAL, "Database Connection String"),
        new PatternConfig("Firebase URL", "https://[a-zA-Z0-9_-]+\\.firebaseio\\.com", Severity.CRITICAL, "Firebase Database URL"),
        new PatternConfig("Firebase Key", "AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", Severity.CRITICAL, "Firebase Server Key"),
        
        // Cloud Services
        new PatternConfig("Twilio Key", "SK[0-9a-fA-F]{32}", Severity.CRITICAL, "Twilio API Key"),
        new PatternConfig("Twilio SID", "AC[a-zA-Z0-9]{32}", Severity.CRITICAL, "Twilio Account SID"),
        new PatternConfig("SendGrid Key", "SG\\.[0-9a-zA-Z_-]{22}\\.[0-9a-zA-Z_-]{43}", Severity.CRITICAL, "SendGrid API Key"),
        new PatternConfig("Mailgun Key", "key-[0-9a-zA-Z]{32}", Severity.CRITICAL, "Mailgun API Key"),
        new PatternConfig("MailChimp Key", "[0-9a-f]{32}-us[0-9]{1,2}", Severity.CRITICAL, "MailChimp API Key"),
        new PatternConfig("Heroku Key", "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", Severity.CRITICAL, "Heroku API Key"),
        new PatternConfig("AWS AppSync", "da2-[a-z0-9]{26}", Severity.CRITICAL, "AWS AppSync API Key"),
        
        // OAuth & Social
        new PatternConfig("Facebook Token", "EAACEdEose0cBA[0-9A-Za-z]+", Severity.CRITICAL, "Facebook Access Token"),
        new PatternConfig("Twitter Token", "[tT][wW][iI][tT][tT][eE][rR].*[0-9a-zA-Z]{35,44}", Severity.CRITICAL, "Twitter API Key"),
        new PatternConfig("LinkedIn Token", "[lL][iI][nN][kK][eE][dD][iI][nN].*[0-9a-zA-Z]{16}", Severity.CRITICAL, "LinkedIn Client ID"),
        new PatternConfig("Square Token", "sq0atp-[0-9A-Za-z_-]{22,}", Severity.CRITICAL, "Square Access Token"),
        new PatternConfig("PayPal Token", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-z]{32}", Severity.CRITICAL, "PayPal Access Token"),
        
        // PII
        new PatternConfig("Credit Card", "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\\d{3})\\d{11})\\b", Severity.CRITICAL, "Credit Card Number"),
        new PatternConfig("SSN", "\\b\\d{3}-\\d{2}-\\d{4}\\b", Severity.CRITICAL, "Social Security Number"),
        
        // ============================================
        // MEDIUM - Endpoints y URLs sensibles
        // ============================================
        new PatternConfig("API Endpoint", "['\"](/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)['\"]", Severity.MEDIUM, "API Endpoint"),
        new PatternConfig("Admin Panel", "['\"](/admin|/dashboard|/manage|/control|/console)[^\"']*['\"]", Severity.MEDIUM, "Admin Panel URL"),
        new PatternConfig("Internal URL", "https?://(?:internal|dev|staging|test|localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)[^\\s\"']*", Severity.MEDIUM, "Internal/Development URL"),
        new PatternConfig("GraphQL Endpoint", "['\"](/graphql|/gql|/query)[^\"']*['\"]", Severity.MEDIUM, "GraphQL Endpoint"),
        new PatternConfig("Websocket", "wss?://[^\\s\"']+", Severity.MEDIUM, "WebSocket URL"),
        new PatternConfig("S3 Bucket", "[a-zA-Z0-9_-]*\\.s3\\.amazonaws\\.com", Severity.MEDIUM, "S3 Bucket URL"),
        new PatternConfig("S3 Bucket Alt", "s3://[a-zA-Z0-9_-]+", Severity.MEDIUM, "S3 Bucket URI"),
        new PatternConfig("Azure Blob", "[a-zA-Z0-9_-]+\\.blob\\.core\\.windows\\.net", Severity.MEDIUM, "Azure Blob Storage"),
        new PatternConfig("GCP Storage", "[a-zA-Z0-9_-]+\\.storage\\.googleapis\\.com", Severity.MEDIUM, "Google Cloud Storage"),
        
        // ============================================
        // LOW - Información potencialmente útil
        // ============================================
        new PatternConfig("Email Address", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Severity.LOW, "Email Address"),
        new PatternConfig("IP Address", "\\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b", Severity.LOW, "IP Address"),
        new PatternConfig("Phone Number", "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b", Severity.LOW, "Phone Number"),
        new PatternConfig("Version String", "['\"]?v?(?:\\d{1,3}\\.){1,3}\\d{1,3}['\"]?", Severity.LOW, "Version Number"),
        new PatternConfig("UUID", "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", Severity.LOW, "UUID"),
        
        // ============================================
        // INFO - Comentarios y debugging
        // ============================================
        new PatternConfig("TODO Comment", "//\\s*TODO.*|/\\*\\s*TODO.*|#\\s*TODO.*", Severity.INFO, "TODO Comment"),
        new PatternConfig("FIXME Comment", "//\\s*FIXME.*|/\\*\\s*FIXME.*|#\\s*FIXME.*", Severity.INFO, "FIXME Comment"),
        new PatternConfig("BUG Comment", "//\\s*BUG.*|/\\*\\s*BUG.*|#\\s*BUG.*", Severity.INFO, "BUG Comment"),
        new PatternConfig("XXX Comment", "//\\s*XXX.*|/\\*\\s*XXX.*|#\\s*XXX.*", Severity.INFO, "XXX Marker"),
        new PatternConfig("HACK Comment", "//\\s*HACK.*|/\\*\\s*HACK.*|#\\s*HACK.*", Severity.MEDIUM, "HACK Comment"),
        new PatternConfig("DEBUG Code", "console\\.(log|debug|warn|error)\\s*\\([^)]{50,}\\)", Severity.INFO, "Debug Statement with Data"),
        new PatternConfig("Disabled Code", "(/\\*|//)\\s*(DISABLED|REMOVED|DEPRECATED)", Severity.INFO, "Disabled/Deprecated Code"),
        new PatternConfig("Config Block", "/\\*\\s*CONFIG[^*]*\\*/", Severity.INFO, "Configuration Block")
    );
    
    private static class PatternConfig {
        final String name;
        final Pattern pattern;
        final Severity severity;
        final String description;
        
        PatternConfig(String name, String regex, Severity severity, String description) {
            this.name = name;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.severity = severity;
            this.description = description;
        }
    }
    
    public static List<Finding> analyze(String content) {
        List<Finding> findings = new ArrayList<>();
        if (content == null || content.isEmpty()) return findings;
        
        String[] lines = content.split("\\r?\\n");
        
        for (PatternConfig config : PATTERNS) {
            Matcher matcher = config.pattern.matcher(content);
            while (matcher.find()) {
                String match = matcher.group();
                int lineNum = findLineNumber(lines, matcher.start());
                
                // Evitar duplicados muy similares
                boolean duplicate = false;
                for (Finding f : findings) {
                    if (f.type.equals(config.name) && f.value.equals(match)) {
                        duplicate = true;
                        break;
                    }
                }
                
                if (!duplicate) {
                    findings.add(new Finding(config.name, match, config.severity, config.description, lineNum));
                }
            }
        }
        
        return findings;
    }
    
    private static int findLineNumber(String[] lines, int position) {
        int charCount = 0;
        for (int i = 0; i < lines.length; i++) {
            charCount += lines[i].length() + 1; // +1 for newline
            if (charCount > position) return i + 1;
        }
        return 1;
    }
    
    public static List<String> extractEndpoints(String content) {
        Set<String> endpoints = new HashSet<>();
        
        // URLs completas
        Pattern urlPattern = Pattern.compile("['\"](https?://[^'\"]+)['\"]");
        Matcher urlMatcher = urlPattern.matcher(content);
        while (urlMatcher.find()) {
            endpoints.add(urlMatcher.group(1));
        }
        
        // Rutas relativas API
        Pattern pathPattern = Pattern.compile("['\"](/[a-zA-Z0-9/_-]+)['\"]");
        Matcher pathMatcher = pathPattern.matcher(content);
        while (pathMatcher.find()) {
            String path = pathMatcher.group(1);
            if (path.contains("api") || path.contains("v1") || path.contains("v2") || 
                path.startsWith("/admin") || path.startsWith("/internal") || path.split("/").length > 2) {
                endpoints.add(path);
            }
        }
        
        // Fetch/XHR endpoints
        Pattern fetchPattern = Pattern.compile("(?:fetch|axios|xhr|request)\\(['\"]([^'\"]+)['\"]");
        Matcher fetchMatcher = fetchPattern.matcher(content);
        while (fetchMatcher.find()) {
            endpoints.add(fetchMatcher.group(1));
        }
        
        return new ArrayList<>(endpoints);
    }
    
    public static String getSeverityColor(Severity severity) {
        switch (severity) {
            case CRITICAL: return "#FF0000";
            case MEDIUM: return "#FFA500";
            case LOW: return "#FFFF00";
            case INFO: default: return "#808080";
        }
    }
    
    public static String getSeverityIcon(Severity severity) {
        switch (severity) {
            case CRITICAL: return "🔴";
            case MEDIUM: return "🟡";
            case LOW: return "🔵";
            case INFO: default: return "⚪";
        }
    }
}
