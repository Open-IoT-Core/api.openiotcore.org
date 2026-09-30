/*
  OpenIoTCore - Firmware ESP32
  Sistema de Control de Acceso Físico Inteligente

  Funciones:
  1. Si el dispositivo NO tiene WiFi configurado, levanta un Access Point
     ("OpenIoTCore-Setup") con un portal cautivo original y completo con escaneo de redes.
  2. Una vez configurado, se conecta a la red WiFi y opera con normalidad:
     - Genera un CÓDIGO DE VINCULACIÓN DE 8 DÍGITOS (ej: AEIO-4283) con vigencia de 1 hora.
     - Muestra el código en la pantalla OLED si el dispositivo aún no ha sido vinculado por un usuario.
     - Valida tarjetas RFID contra la API de OpenIoTCore (/api/v1/access/validate).
     - Soporta conexiones HTTP (puerto 4000) y HTTPS (puerto 443 / SSL / TLS).
     - Conexión WebSocket (WS / WSS) activa para recibir comandos de APERTURA REMOTA desde la Web.
     - Sincronización de credenciales offline (/api/v1/access/offline-sync).
     - Muestra estado en el OLED SSD1327 y controla el Servo motor.

  PINES PRESERVADOS SIN MODIFICAR:
    RC522 -> SPI (SCK=18, MISO=19, MOSI=23, SS=5, RST=4)
    OLED  -> I2C (SDA=21, SCL=22)
    SERVO -> GPIO13
*/

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1327.h>
#include <ESP32Servo.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>

// ============================================================
// PINES EXACTOS DEL CÓDIGO ORIGINAL (SIN MODIFICAR)
// ============================================================
#define RFID_SCK   18
#define RFID_MISO  19
#define RFID_MOSI  23
#define RFID_SS    5
#define RFID_RST   4

#define OLED_SDA   21
#define OLED_SCL   22

#define SERVO_PIN  13

// LEDS / BUZZER OPCIONALES (GPIOs libres)
#define LED_GREEN_PIN 12
#define LED_RED_PIN   14
#define BUZZER_PIN    15

// ============================================================
// CONFIGURACIÓN DE RED / API
// ============================================================
const char* AP_SSID = "OpenIoTCore-Setup";
const char* AP_PASS = "openiotcore123";

// Configuración de Servidor Backend OpenIoTCore
String apiHost           = "api.openiotcore.org"; // Se puede cambiar o guardar en NVS
int    apiPort           = 443;
const char* API_VALIDATE_URI = "/api/v1/access/validate";

// Tiempo que la cerradura/servo permanece "abierta"
const unsigned long DURACION_APERTURA_MS = 5000;
const unsigned long TIMEOUT_WIFI_MS = 15000;

// ============================================================
// ESTADO GLOBAL
// ============================================================
Preferences cfgPrefs;    // namespace "cfg"
Preferences cachePrefs;  // namespace "access_cache"

DNSServer dnsServer;
WebServer webServer(80);
WebSocketsClient webSocket;
const byte DNS_PORT = 53;

MFRC522 rfid(RFID_SS, RFID_RST);
Adafruit_SSD1327 display(128, 128, &Wire, -1);
Servo miServo;

bool modoAP = false;
bool servoActivo = false;
bool dispositivoVinculado = false;
unsigned long tiempoActivacion = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastOfflineSync = 0;
unsigned long pairingCodeGeneratedAt = 0;

String deviceId;
String wifiSsid;
String wifiPass;
String pairingCode = "";

// ============================================================
// UTILIDADES DE PANTALLA OLED
// ============================================================
void mostrarMensaje(const String& linea1, const String& linea2 = "", const String& linea3 = "") {
  display.clearDisplay();
  display.setTextColor(SSD1327_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("== OpenIoTCore ==");
  display.setCursor(0, 20);
  display.println(linea1);
  if (linea2 != "") {
    display.setCursor(0, 45);
    display.println(linea2);
  }
  if (linea3 != "") {
    display.setCursor(0, 70);
    display.println(linea3);
  }
  display.display();
}

// Genera un código de vinculación de 8 caracteres (ej: AEIO-4283)
String generarCodigoVinculacion() {
  const char chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  uint32_t r = esp_random();
  randomSeed(micros() + r);
  String code = "";
  for (int i = 0; i < 4; i++) {
    code += chars[esp_random() % strlen(chars)];
  }
  code += "-";
  for (int i = 0; i < 4; i++) {
    code += chars[esp_random() % strlen(chars)];
  }
  return code;
}

// ============================================================
// PORTAL CAUTIVO ORIGINAL (CON ESCANEO Y DISEÑO ORIGINAL)
// ============================================================
const char PORTAL_HTML[] PROGMEM = R"HTML(
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configurar OpenIoTCore</title>
<style>
  body{font-family:Arial,Helvetica,sans-serif;background:#101826;color:#e6ebf0;
       margin:0;padding:24px;display:flex;justify-content:center;}
  .card{background:#16212c;padding:24px;border-radius:10px;max-width:360px;width:100%;}
  h1{font-size:18px;margin:0 0 4px;color:#e8a33d;}
  p{font-size:13px;color:#93a3b1;margin:0 0 16px;}
  label{display:block;font-size:12px;margin:14px 0 6px;color:#c4d0da;}
  input,select{width:100%;padding:10px;border-radius:6px;border:1px solid #2a3947;
       background:#0e1720;color:#e6ebf0;box-sizing:border-box;font-size:14px;}
  button{margin-top:20px;width:100%;padding:12px;border:none;border-radius:6px;
       background:#e8a33d;color:#101826;font-weight:bold;font-size:14px;cursor:pointer;}
  button:disabled{background:#4a4030;color:#8a8a8a;cursor:not-allowed;}
  button.secundario{background:transparent;border:1px solid #2a3947;color:#c4d0da;
       font-weight:normal;margin-top:8px;}
  .red-lista{max-height:220px;overflow-y:auto;border:1px solid #2a3947;border-radius:6px;}
  .red-item{display:flex;justify-content:space-between;align-items:center;
       padding:10px 12px;font-size:13px;cursor:pointer;border-bottom:1px solid #1c2733;}
  .red-item:last-child{border-bottom:none;}
  .red-item:hover{background:#1c2733;}
  .red-item.seleccionada{background:#233042;}
  .red-nombre{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;}
  .red-tag{font-size:10px;padding:2px 6px;border-radius:4px;margin-left:8px;flex-shrink:0;}
  .red-tag.abierta{background:#3a2a1a;color:#e8a33d;}
  .red-tag.segura{background:#1a2e2a;color:#6fb98f;}
  .cargando{padding:14px;font-size:13px;color:#93a3b1;text-align:center;}
  .aviso-riesgo{display:none;margin-top:14px;padding:12px;border-radius:6px;
       background:#2a1a1a;border:1px solid #6b2c2c;font-size:12px;color:#f0b4ae;line-height:1.5;}
  .aviso-riesgo.visible{display:block;}
  .aviso-riesgo label{display:flex;align-items:flex-start;gap:8px;color:#f0b4ae;
       margin-top:10px;font-size:12px;}
  .aviso-riesgo input[type=checkbox]{width:auto;margin-top:2px;}
  .manual-toggle{font-size:12px;color:#7fa8d9;text-align:right;margin-top:8px;cursor:pointer;
       text-decoration:underline;}
  #campo-manual{display:none;margin-top:6px;}
</style>
</head>
<body>
  <div class="card">
    <h1>OpenIoTCore &middot; Configuración</h1>
    <p>Elige la red WiFi del local para conectar este nodo.</p>

    <div id="lista-redes" class="red-lista">
      <div class="cargando">Buscando redes cercanas...</div>
    </div>
    <div class="manual-toggle" id="toggle-manual">¿No aparece tu red? Ingrésala manualmente</div>
    <div id="campo-manual">
      <label for="ssid_manual">Nombre de la red (SSID)</label>
      <input type="text" id="ssid_manual" placeholder="Nombre exacto de la red">
    </div>

    <form action="/save" method="POST" id="form-config">
      <input type="hidden" id="ssid" name="ssid" required>

      <label for="pass">Contraseña</label>
      <input type="password" id="pass" name="pass" placeholder="Selecciona una red primero">

      <div class="aviso-riesgo" id="aviso-riesgo">
        ⚠️ Esta red no tiene contraseña (es una red abierta). Se recomienda
        usar una red con contraseña (WPA2/WPA3).
        <label>
          <input type="checkbox" id="acepto-riesgo">
          Entiendo el riesgo y quiero continuar de todas formas.
        </label>
      </div>

      <label for="host">Servidor Backend (IP o Host)</label>
      <input type="text" id="host" name="host" value="%API_HOST%">

      <label for="port">Puerto Backend</label>
      <input type="number" id="port" name="port" value="%API_PORT%">

      <label for="device_id">ID del dispositivo</label>
      <input type="text" id="device_id" name="device_id" value="%DEVICE_ID%">

      <button type="submit" id="btn-guardar" disabled>Selecciona una red primero</button>
      <button type="button" class="secundario" id="btn-rescan">Buscar redes de nuevo</button>
    </form>
  </div>

<script>
  var redSeleccionada = null;
  var listaEl = document.getElementById('lista-redes');
  var ssidInput = document.getElementById('ssid');
  var passInput = document.getElementById('pass');
  var avisoEl = document.getElementById('aviso-riesgo');
  var aceptoRiesgo = document.getElementById('acepto-riesgo');
  var btnGuardar = document.getElementById('btn-guardar');

  function actualizarBotonGuardar() {
    if (!redSeleccionada) {
      btnGuardar.disabled = true;
      btnGuardar.textContent = 'Selecciona una red primero';
      return;
    }
    if (!redSeleccionada.secure && !aceptoRiesgo.checked) {
      btnGuardar.disabled = true;
      btnGuardar.textContent = 'Confirma que entiendes el riesgo';
      return;
    }
    btnGuardar.disabled = false;
    btnGuardar.textContent = 'Guardar y conectar';
  }

  function seleccionarRed(ssid, secure) {
    redSeleccionada = { ssid: ssid, secure: secure };
    ssidInput.value = ssid;

    document.querySelectorAll('.red-item').forEach(function (el) {
      el.classList.toggle('seleccionada', el.dataset.ssid === ssid);
    });

    if (secure) {
      avisoEl.classList.remove('visible');
      aceptoRiesgo.checked = false;
      passInput.placeholder = 'Contraseña de ' + ssid;
      passInput.disabled = false;
      passInput.required = true;
    } else {
      avisoEl.classList.add('visible');
      passInput.value = '';
      passInput.placeholder = 'No aplica (red abierta)';
      passInput.disabled = true;
      passInput.required = false;
    }
    actualizarBotonGuardar();
  }

  function pintarRedes(redes) {
    if (!redes.length) {
      listaEl.innerHTML = '<div class="cargando">No se encontraron redes. Intenta de nuevo.</div>';
      return;
    }
    var vistos = {};
    redes = redes.filter(function (r) {
      if (vistos[r.ssid]) return false;
      vistos[r.ssid] = true;
      return r.ssid.length > 0;
    });
    redes.sort(function (a, b) { return b.rssi - a.rssi; });

    listaEl.innerHTML = '';
    redes.forEach(function (r) {
      var item = document.createElement('div');
      item.className = 'red-item';
      item.dataset.ssid = r.ssid;
      item.innerHTML = '<span class="red-nombre">' + r.ssid + '</span>' +
        '<span class="red-tag ' + (r.secure ? 'segura' : 'abierta') + '">' +
        (r.secure ? 'Protegida' : 'Abierta') + '</span>';
      item.addEventListener('click', function () { seleccionarRed(r.ssid, r.secure); });
      listaEl.appendChild(item);
    });
  }

  var intentos = 0;
  function buscarRedes() {
    listaEl.innerHTML = '<div class="cargando">Buscando redes cercanas...</div>';
    intentos = 0;
    poll();
  }

  function poll() {
    fetch('/scan').then(function (res) { return res.json().then(function (data) { return { status: res.status, data: data }; }); })
      .then(function (r) {
        if (r.status === 200) {
          pintarRedes(r.data);
        } else if (intentos < 8) {
          intentos++;
          setTimeout(poll, 1200);
        } else {
          listaEl.innerHTML = '<div class="cargando">No se pudo completar el escaneo.</div>';
        }
      })
      .catch(function () {
        listaEl.innerHTML = '<div class="cargando">Error al buscar redes.</div>';
      });
  }

  document.getElementById('btn-rescan').addEventListener('click', buscarRedes);
  aceptoRiesgo.addEventListener('change', actualizarBotonGuardar);

  document.getElementById('toggle-manual').addEventListener('click', function () {
    var campo = document.getElementById('campo-manual');
    var visible = campo.style.display === 'block';
    campo.style.display = visible ? 'none' : 'block';
  });

  document.getElementById('ssid_manual').addEventListener('input', function (e) {
    if (e.target.value.trim().length > 0) {
      seleccionarRed(e.target.value.trim(), true);
    }
  });

  buscarRedes();
</script>
</body>
</html>
)HTML";

void handlePortalRoot() {
  String html = String(PORTAL_HTML);
  html.replace("%DEVICE_ID%", deviceId);
  html.replace("%API_HOST%", apiHost);
  html.replace("%API_PORT%", String(apiPort));
  webServer.send(200, "text/html", html);
}

String escaparJson(const String& texto) {
  String out;
  out.reserve(texto.length() + 4);
  for (size_t i = 0; i < texto.length(); i++) {
    char c = texto[i];
    if (c == '"' || c == '\\') out += '\\';
    out += c;
  }
  return out;
}

void handlePortalScan() {
  int n = WiFi.scanComplete();

  if (n == WIFI_SCAN_FAILED) {
    WiFi.scanNetworks(true, false);
    webServer.send(202, "application/json", "[]");
    return;
  }
  if (n == WIFI_SCAN_RUNNING) {
    webServer.send(202, "application/json", "[]");
    return;
  }

  String json = "[";
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    bool esAbierta = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN);
    json += "{\"ssid\":\"" + escaparJson(WiFi.SSID(i)) + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"secure\":" + String(esAbierta ? "false" : "true") + "}";
  }
  json += "]";
  WiFi.scanDelete();

  webServer.send(200, "application/json", json);
}

void handlePortalSave() {
  String ssid = webServer.arg("ssid");
  String pass = webServer.arg("pass");
  String devId = webServer.arg("device_id");
  String host  = webServer.arg("host");
  int port    = webServer.arg("port").toInt();

  if (port <= 0) port = 443;
  if (host == "") host = "api.openiotcore.org";

  cfgPrefs.putString("ssid", ssid);
  cfgPrefs.putString("pass", pass);
  cfgPrefs.putString("device_id", devId);
  cfgPrefs.putString("host", host);
  cfgPrefs.putInt("port", port);
  cfgPrefs.putBool("configured", true);

  webServer.send(200, "text/html",
    "<html><body style='font-family:sans-serif;background:#101826;color:#6fb98f;text-align:center;padding-top:60px;'>"
    "<h2>Configuración guardada exitosamente</h2>"
    "<p style='color:#e6ebf0;'>El dispositivo se reiniciará para conectarse a " + ssid + "...</p>"
    "</body></html>");

  delay(1500);
  ESP.restart();
}

void handlePortalNotFound() {
  webServer.sendHeader("Location", "http://192.168.4.1/", true);
  webServer.send(302, "text/plain", "");
}

void iniciarPortalCautivo() {
  modoAP = true;
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  WiFi.scanNetworks(true);

  IPAddress apIP = WiFi.softAPIP();
  dnsServer.start(DNS_PORT, "*", apIP);

  webServer.on("/", handlePortalRoot);
  webServer.on("/scan", HTTP_GET, handlePortalScan);
  webServer.on("/save", HTTP_POST, handlePortalSave);
  webServer.onNotFound(handlePortalNotFound);
  webServer.begin();

  Serial.println("[AP] Portal Cautivo activo.");
  Serial.print("[AP] SSID: "); Serial.println(AP_SSID);
  Serial.print("[AP] IP:   "); Serial.println(apIP);

  mostrarMensaje("Modo Config:", String("Red: ") + AP_SSID, "IP: 192.168.4.1");
}

// ============================================================
// REGISTRO DE CÓDIGO DE VINCULACIÓN (8 DÍGITOS / 1 HORA)
// ============================================================
void anunciarCodigoVinculacion() {
  if (WiFi.status() != WL_CONNECTED) return;

  pairingCode = generarCodigoVinculacion();
  pairingCodeGeneratedAt = millis();

  String cleanHost = apiHost;
  cleanHost.replace("http://", "");
  cleanHost.replace("https://", "");
  bool isSSL = (apiPort == 443 || apiHost.startsWith("https://"));

  String protocol = isSSL ? "https://" : "http://";
  String url = protocol + cleanHost;
  if (apiPort != 80 && apiPort != 443) {
    url += ":" + String(apiPort);
  }
  url += "/api/v1/access/announce-pairing";

  HTTPClient http;
  WiFiClientSecure secureClient;
  bool beginOk = false;

  if (isSSL) {
    secureClient.setInsecure();
    beginOk = http.begin(secureClient, url);
  } else {
    beginOk = http.begin(url);
  }

  if (beginOk) {
    http.addHeader("Content-Type", "application/json");
    StaticJsonDocument<200> doc;
    doc["device_id"]    = deviceId;
    doc["pairing_code"] = pairingCode;
    doc["mac_address"]  = WiFi.macAddress();

    String body;
    serializeJson(doc, body);
    int code = http.POST(body);

    if (code == 200) {
      Serial.println("[PAIRING] Código de vinculación registrado en la API: " + pairingCode);
    } else {
      Serial.printf("[PAIRING] Error al registrar código: %d\n", code);
    }
    http.end();
  }
}

void verificarEstadoVinculacion() {
  if (WiFi.status() != WL_CONNECTED) return;

  String cleanHost = apiHost;
  cleanHost.replace("http://", "");
  cleanHost.replace("https://", "");
  bool isSSL = (apiPort == 443 || apiHost.startsWith("https://"));

  String protocol = isSSL ? "https://" : "http://";
  String url = protocol + cleanHost;
  if (apiPort != 80 && apiPort != 443) {
    url += ":" + String(apiPort);
  }
  url += "/api/v1/access/check-pairing/" + deviceId;

  HTTPClient http;
  WiFiClientSecure secureClient;
  bool beginOk = false;

  if (isSSL) {
    secureClient.setInsecure();
    beginOk = http.begin(secureClient, url);
  } else {
    beginOk = http.begin(url);
  }

  if (beginOk) {
    int code = http.GET();
    if (code == 200) {
      StaticJsonDocument<200> doc;
      if (!deserializeJson(doc, http.getString())) {
        dispositivoVinculado = doc["vinculado"] | false;
        if (!dispositivoVinculado) {
          mostrarMensaje("Cod. Vinculacion:", pairingCode, "Vigente: 1 hora");
        } else {
          mostrarMensaje("Listo.", "Acerca tu tarjeta");
        }
      }
    }
    http.end();
  }
}

// ============================================================
// CONEXIÓN WEBSOCKETS (WS HTTP O WSS HTTPS)
// ============================================================
void initWebSockets() {
  String wsUrl = "/ws?type=device&deviceId=" + deviceId;

  String cleanHost = apiHost;
  cleanHost.replace("http://", "");
  cleanHost.replace("https://", "");

  bool isSSL = (apiPort == 443 || apiHost.startsWith("https://"));

  if (isSSL) {
    webSocket.beginSSL(cleanHost.c_str(), apiPort, wsUrl.c_str());
  } else {
    webSocket.begin(cleanHost.c_str(), apiPort, wsUrl.c_str());
  }

  webSocket.onEvent([](WStype_t type, uint8_t * payload, size_t length) {
    switch (type) {
      case WStype_CONNECTED:
        Serial.println("[WS] WebSocket Conectado al Backend!");
        break;
      case WStype_TEXT: {
        StaticJsonDocument<512> doc;
        if (!deserializeJson(doc, payload)) {
          const char* eventName = doc["event"];
          const char* command   = doc["command"];

          if (eventName && strcmp(eventName, "paired") == 0) {
            Serial.println("[WS-EVENT] ¡Dispositivo vinculado con éxito por el usuario!");
            dispositivoVinculado = true;
            mostrarMensaje("¡Vinculado!", "Cerradura lista", "Acerca tu tarjeta");
            delay(2000);
          } else if (command && strcmp(command, "UNLOCK") == 0) {
            Serial.println("[WS-CMD] ¡Orden de apertura remota recibida!");
            mostrarMensaje("Desbloqueo Web", "Acceso concedido", "WebSocket");
            abrirCerradura();
          }
        }
        break;
      }
      default:
        break;
    }
  });
  webSocket.setReconnectInterval(5000);
}

// ============================================================
// CONEXIÓN WIFI NORMAL
// ============================================================
bool conectarWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());

  Serial.print("[WIFI] Conectando a "); Serial.println(wifiSsid);
  mostrarMensaje("Conectando WiFi", wifiSsid);

  unsigned long inicio = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - inicio < TIMEOUT_WIFI_MS) {
    delay(300);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("[WIFI] Conectado. IP: ");
    Serial.println(WiFi.localIP());
    return true;
  }

  Serial.println("[WIFI] No se pudo conectar.");
  return false;
}

// ============================================================
// CACHÉ OFFLINE Y SINCRONIZACIÓN
// ============================================================
bool consultarCacheLocal(const String& uid) {
  return cachePrefs.getBool(uid.c_str(), false);
}

void actualizarCacheLocal(const String& uid, bool permitido) {
  cachePrefs.putBool(uid.c_str(), permitido);
}

void syncOfflineCredentials() {
  if (WiFi.status() != WL_CONNECTED) return;

  String cleanHost = apiHost;
  cleanHost.replace("http://", "");
  cleanHost.replace("https://", "");
  bool isSSL = (apiPort == 443 || apiHost.startsWith("https://"));

  String protocol = isSSL ? "https://" : "http://";
  String url = protocol + cleanHost;
  if (apiPort != 80 && apiPort != 443) {
    url += ":" + String(apiPort);
  }
  url += "/api/v1/access/offline-sync?device_id=" + deviceId;

  HTTPClient http;
  WiFiClientSecure secureClient;
  bool beginOk = false;

  if (isSSL) {
    secureClient.setInsecure();
    beginOk = http.begin(secureClient, url);
  } else {
    beginOk = http.begin(url);
  }

  if (beginOk) {
    int code = http.GET();
    if (code == 200) {
      DynamicJsonDocument doc(4096);
      if (!deserializeJson(doc, http.getString())) {
        JsonArray creds = doc["credenciales_autorizadas"];
        for (JsonObject c : creds) {
          const char* uid = c["uid_hex"];
          if (uid) {
            actualizarCacheLocal(String(uid), true);
          }
        }
        Serial.println("[SYNC] Credenciales offline sincronizadas correctamente.");
      }
    }
    http.end();
  }
}

// ============================================================
// VALIDACIÓN EN LÍNEA CONTRA LA API (REST HTTP / HTTPS)
// ============================================================
bool validarConAPI(const String& uid, bool& accessGranted) {
  if (WiFi.status() != WL_CONNECTED) return false;

  String cleanHost = apiHost;
  cleanHost.replace("http://", "");
  cleanHost.replace("https://", "");
  bool isSSL = (apiPort == 443 || apiHost.startsWith("https://"));

  String protocol = isSSL ? "https://" : "http://";
  String url = protocol + cleanHost;
  if (apiPort != 80 && apiPort != 443) {
    url += ":" + String(apiPort);
  }
  url += API_VALIDATE_URI;

  HTTPClient http;
  WiFiClientSecure secureClient;
  bool beginOk = false;

  if (isSSL) {
    secureClient.setInsecure();
    beginOk = http.begin(secureClient, url);
  } else {
    beginOk = http.begin(url);
  }

  if (!beginOk) {
    Serial.println("[API] No se pudo iniciar la conexión HTTP/HTTPS.");
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);

  StaticJsonDocument<200> reqDoc;
  reqDoc["device_id"] = deviceId;
  reqDoc["uid_hex"]   = uid;
  String body;
  serializeJson(reqDoc, body);

  int codigo = http.POST(body);

  if (codigo == 200) {
    String respuesta = http.getString();
    StaticJsonDocument<256> resDoc;
    DeserializationError err = deserializeJson(resDoc, respuesta);
    http.end();

    if (err) {
      Serial.println("[API] Respuesta JSON inválida.");
      return false;
    }

    accessGranted = resDoc["access_granted"] | false;
    actualizarCacheLocal(uid, accessGranted);
    return true;
  }

  Serial.printf("[API] Error HTTP: %d\n", codigo);
  http.end();
  return false;
}

// ============================================================
// ACTUADOR (SERVO & INDICADORES)
// ============================================================
void abrirCerradura() {
  miServo.write(90);
  digitalWrite(LED_GREEN_PIN, HIGH);
  tone(BUZZER_PIN, 2000, 150);
  servoActivo = true;
  tiempoActivacion = millis();
}

void cerrarCerradura() {
  miServo.write(0);
  digitalWrite(LED_GREEN_PIN, LOW);
  servoActivo = false;
}

void revisarTemporizadorServo() {
  if (servoActivo && (millis() - tiempoActivacion >= DURACION_APERTURA_MS)) {
    cerrarCerradura();
    if (!dispositivoVinculado) {
      mostrarMensaje("Cod. Vinculacion:", pairingCode, "Vigente: 1 hora");
    } else {
      mostrarMensaje("Acerca tu tarjeta", modoAP ? "" : WiFi.SSID());
    }
  }
}

// ============================================================
// LECTURA RFID Y FLUJO PRINCIPAL
// ============================================================
String leerUID() {
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void procesarTarjeta() {
  String uid = leerUID();
  Serial.println("[RFID] UID leído: " + uid);

  bool accessGranted = false;
  bool online = validarConAPI(uid, accessGranted);

  if (!online) {
    accessGranted = consultarCacheLocal(uid);
    Serial.println("[MODO] Offline - usando caché local NVS");
  }

  if (accessGranted) {
    Serial.println("[ACCESO] Permitido. Abriendo cerradura...");
    mostrarMensaje("Acceso concedido", uid, online ? "En linea" : "Modo offline");
    abrirCerradura();
  } else {
    Serial.println("[ACCESO] Denegado.");
    digitalWrite(LED_RED_PIN, HIGH);
    tone(BUZZER_PIN, 500, 300);
    mostrarMensaje("Acceso denegado", uid, online ? "En linea" : "Modo offline");
    delay(400);
    digitalWrite(LED_RED_PIN, LOW);
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}

// ============================================================
// SETUP / LOOP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  // Inicializar LEDs y Buzzer
  pinMode(LED_GREEN_PIN, OUTPUT);
  pinMode(LED_RED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(LED_GREEN_PIN, LOW);
  digitalWrite(LED_RED_PIN, LOW);

  // Inicialización I2C y OLED SSD1327 en PINES ORIGINALES 21/22
  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(0x3D)) {
    if (!display.begin(0x3C)) {
      Serial.println("[OLED] No se detectó el display.");
    }
  }
  mostrarMensaje("Iniciando...", "OpenIoTCore");

  // Inicialización SPI y MFRC522 en PINES ORIGINALES 18/19/23/5/4
  SPI.begin(RFID_SCK, RFID_MISO, RFID_MOSI, RFID_SS);
  rfid.PCD_Init();

  // Inicialización Servo en PIN ORIGINAL 13
  miServo.attach(SERVO_PIN);
  miServo.write(0);

  cfgPrefs.begin("cfg", false);
  cachePrefs.begin("access_cache", false);

  bool configurado = cfgPrefs.getBool("configured", false);
  deviceId = cfgPrefs.getString("device_id", "");
  apiHost  = cfgPrefs.getString("host", "api.openiotcore.org");
  apiPort  = cfgPrefs.getInt("port", 443);

  if (deviceId == "") {
    deviceId = "ESP32-" + WiFi.macAddress();
    deviceId.replace(":", "");
  }

  if (!configurado) {
    iniciarPortalCautivo();
    return;
  }

  wifiSsid = cfgPrefs.getString("ssid", "");
  wifiPass = cfgPrefs.getString("pass", "");

  if (!conectarWifi()) {
    iniciarPortalCautivo();
    return;
  }

  initWebSockets();
  syncOfflineCredentials();
  anunciarCodigoVinculacion();
  verificarEstadoVinculacion();

  Serial.println("[SYSTEM] Dispositivo listo. Device ID: " + deviceId);
}

void loop() {
  if (modoAP) {
    dnsServer.processNextRequest();
    webServer.handleClient();
    return;
  }

  webSocket.loop();
  revisarTemporizadorServo();

  // Expiración del código de 1 hora
  if (!dispositivoVinculado && pairingCodeGeneratedAt > 0 && (millis() - pairingCodeGeneratedAt > 3600000)) {
    Serial.println("[PAIRING] El código de 1 hora ha expirado. Re-anunciando nuevo código...");
    anunciarCodigoVinculacion();
    verificarEstadoVinculacion();
  }

  if (millis() - lastHeartbeat > 30000) {
    lastHeartbeat = millis();
    if (webSocket.isConnected()) {
      webSocket.sendTXT("{\"event\":\"heartbeat\"}");
    }
  }

  if (millis() - lastOfflineSync > 300000) {
    lastOfflineSync = millis();
    syncOfflineCredentials();
  }

  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

  procesarTarjeta();
  delay(800);
}
