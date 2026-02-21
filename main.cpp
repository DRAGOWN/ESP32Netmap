#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>

const char* ssid = "Your_SSID";
const char* password = "Your_PSK";

AsyncWebServer server(80);

// Helper to convert IPAddress to String
String ipToString(IPAddress ip) {
  return String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2]) + "." + String(ip[3]);
}

// CORE SCANNER: Scans a single IP for specific ports
String scanTarget(String ipStr, String portsStr) {
    String log = ">> Scanning " + ipStr + "\n";
    WiFiClient client;
    // Default ports if none provided
    int ports[] = {
    // --- Infrastructure & Remote Access ---
    21,   // FTP
    22,   // SSH
    23,   // Telnet (Critical for IoT/Legacy)
    25,   // SMTP
    53,   // DNS
    80,   // HTTP
    110,  // POP3
    135,  // RPC
    139,  // NetBIOS
    143,  // IMAP
    443,  // HTTPS
    445,  // SMB (Active Directory / File Shares)
    587,  // SMTP SSL
    993,  // IMAP SSL
    995,  // POP3 SSL
    
    // --- Databases ---
    1433, // MSSQL
    3306, // MySQL / MariaDB
    5432, // PostgreSQL
    6379, // Redis
    27017,// MongoDB
    
    // --- Remote Desktop & Virtualization ---
    3389, // RDP (Windows Remote Desktop)
    5900, // VNC
    5901, // VNC Display :1
    8000, // Common Development Servers
    8080, // HTTP Proxy / Alternate
    8443, // HTTPS Alternate
    8888, // MWS / Development
    9000, // Portainer / PHP-FPM
    
    // --- Industrial & IoT ---
    1883, // MQTT
    5000, // Flask / Docker
    8081, // Common IP Camera / IoT UI
    8899, // ONVIF (IP Cameras)
    10000 // Webmin
};
    
    for (int p : ports) {
        // We use a 150ms timeout to balance speed and reliability in Dual Mode
        if (client.connect(ipStr.c_str(), p, 150)) {
            log += "[+] PORT " + String(p) + " OPEN\n";
            client.stop();
        }
        yield(); // Crucial to prevent AP disconnects
    }
    return log;
}

// RANGE PARSER: Handles 192.168.0.1-100 or 192.168.0.0/24
void handleAdvancedScan(AsyncWebServerRequest *request) {
    if (!request->hasParam("target")) {
        request->send(400, "text/plain", "Missing target");
        return;
    }

    String input = request->getParam("target")->value();
    String results = "--- MULTI-TARGET SCAN START ---\n";
    
    // Logic for CIDR /24
    if (input.endsWith("/24")) {
        String base = input.substring(0, input.lastIndexOf('.') + 1);
        for (int i = 1; i < 255; i++) {
            results += scanTarget(base + String(i), "");
        }
    } 
    // Logic for Range (e.g., .4-100)
    else if (input.indexOf('-') != -1) {
        int dotPos = input.lastIndexOf('.');
        int dashPos = input.indexOf('-');
        String base = input.substring(0, dotPos + 1);
        int start = input.substring(dotPos + 1, dashPos).toInt();
        int end = input.substring(dashPos + 1).toInt();
        
        for (int i = start; i <= end; i++) {
            results += scanTarget(base + String(i), "");
        }
    } 
    // Single IP
    else {
        results += scanTarget(input, "");
    }

    request->send(200, "text/plain", results + "\n--- SCAN COMPLETE ---");
}

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><title>ESP32NETMAP</title>
<style>
    body { background:#050505; color:#00ff00; font-family:monospace; padding:20px; }
    #console { background:#000; border:1px solid #00ff00; height:500px; overflow-y:auto; padding:15px; white-space:pre-wrap; }
    input { background:#111; color:#0f0; border:1px solid #0f0; padding:10px; width:300px; margin:10px 0; }
    button { background:#0f0; color:#000; border:none; padding:10px 20px; cursor:pointer; font-weight:bold; }
</style></head><body>
    <h2>ESP32NETMAP</h2>
    <div id="console">SYSTEM READY...</div>
    <input type="text" id="target" placeholder="192.168.0.1-50 OR 192.168.0.0/24">
    <button onclick="run()">EXECUTE SCAN</button>
<script>
    function run() {
        const t = document.getElementById('target').value;
        const c = document.getElementById('console');
        c.innerHTML = "> Initializing Attack Vector on: " + t + "\n";
        fetch('/adv-scan?target=' + t).then(r => r.text()).then(data => { c.innerHTML = data; });
    }
</script></body></html>)rawliteral";

void setup() {
    Serial.begin(115200);
    
    // Set to Dual Mode
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(ssid, password);
    WiFi.softAP("ESP32NETMAP", "password123");

    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        request->send_P(200, "text/html", index_html);
    });

    server.on("/adv-scan", HTTP_GET, handleAdvancedScan);

    server.begin();
}

void loop() {}
