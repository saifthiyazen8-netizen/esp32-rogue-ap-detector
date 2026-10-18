#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include "esp_wifi.h"

// ---------- الإعدادات ----------
#define BTN_NEXT 25
#define BTN_PREV 14
#define LED_GREEN 12
#define LED_RED 13
#define MAX_NETS 100

#define DOUBLE_MS 400          // أقصى مدة بين الضغطتين
#define HIDDEN_LISTEN_MS 8000  // مدة الاستماع لكل شبكة مخفية

// true = شبكات تجريبية
// false = الشبكات الحقيقية فقط
#define DEMO_MODE false

LiquidCrystal_I2C lcd(0x27, 16, 2);

// ---------- القائمة البيضاء ----------
struct Trusted {
  const char* ssid;
  const char* bssid;
};

Trusted trustedList[] = {
  {"Wokwi-GUEST", ""},
  {"Home_WiFi", "AA:BB:CC:11:22:33"}
};

const int trustedCount =
  sizeof(trustedList) / sizeof(trustedList[0]);

// ---------- بيانات الشبكات ----------
struct Net {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  wifi_auth_mode_t enc;
  bool hidden;
  int risk;
  String reason;
  int level;
  String real;   // الاسم الحقيقي للشبكة المخفية بعد كشفه
};

Net nets[MAX_NETS];

int netCount = 0;
int cur = 0;
int page = 0;
bool started = false;

// ---------- نوع التشفير ----------
const char* encName(wifi_auth_mode_t e) {
  switch (e) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3-PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "UNKNOWN";
  }
}

// ---------- التحقق من الشبكات الموثوقة ----------
bool isTrusted(const String& ssid, const String& bssid) {
  for (int i = 0; i < trustedCount; i++) {
    if (ssid == trustedList[i].ssid) {
      if (strlen(trustedList[i].bssid) == 0)
        return true;

      if (bssid.equalsIgnoreCase(trustedList[i].bssid))
        return true;
    }
  }
  return false;
}

bool inTrustedSsid(const String& ssid) {
  for (int i = 0; i < trustedCount; i++) {
    if (ssid == trustedList[i].ssid)
      return true;
  }
  return false;
}

// ---------- إضافة شبكة ----------
void addNet(String ssid, String bssid, int rssi,
            int ch, wifi_auth_mode_t enc) {
  if (netCount >= MAX_NETS) return;

  Net& n = nets[netCount++];

  n.ssid = ssid;
  n.bssid = bssid;
  n.rssi = rssi;
  n.channel = ch;
  n.enc = enc;
  n.hidden = (ssid.length() == 0);
  n.risk = 0;
  n.reason = "";
  n.level = 0;
  n.real = "";
}

// ---------- تحليل المخاطر ----------
void analyze() {
  for (int i = 0; i < netCount; i++) {
    Net& n = nets[i];

    int risk = 0;
    String why = "";

    bool trusted =
      !n.hidden && isTrusted(n.ssid, n.bssid);

    if (!n.hidden && !trusted &&
        inTrustedSsid(n.ssid)) {
      risk += 60;
      why = "Evil Twin!";
    }

    if (!n.hidden && !trusted) {
      for (int j = 0; j < netCount; j++) {
        if (j != i && nets[j].ssid == n.ssid) {
          risk += 25;
          if (why == "") why = "Duplicate SSID";
          break;
        }
      }
    }

    if (!trusted) {
      if (n.enc == WIFI_AUTH_OPEN) {
        risk += 35;
        if (why == "") why = "Open network";
      }
      else if (n.enc == WIFI_AUTH_WEP) {
        risk += 40;
        if (why == "") why = "WEP weak";
      }
      else if (n.enc == WIFI_AUTH_WPA_PSK) {
        risk += 20;
        if (why == "") why = "WPA old";
      }
    }

    if (n.hidden) {
      risk += 25;
      if (why == "") why = "Hidden SSID";
    }

    if (!trusted && n.rssi > -35) {
      risk += 10;
      if (why == "") why = "Very strong sig";
    }

    if (trusted) {
      risk = 0;
      why = "In whitelist";
    }

    if (risk > 100) risk = 100;

    n.risk = risk;
    n.reason = (why == "") ? "No issues" : why;

    if (risk >= 60)
      n.level = 2;
    else if (risk >= 30)
      n.level = 1;
    else
      n.level = 0;
  }
}

// ---------- كشف أسماء الشبكات المخفية ----------
struct Reveal {
  uint8_t bssid[6];
  char ssid[33];
};
Reveal revealed[20];
volatile int revealCount = 0;

void IRAM_ATTR sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 40) return;

  uint8_t sub = (f[0] >> 4) & 0x0F;
  int tag;
  const uint8_t* ap;

  if (sub == 5)      { tag = 36; ap = f + 10; }  // Probe Response
  else if (sub == 0) { tag = 28; ap = f + 4;  }  // Association Request
  else if (sub == 2) { tag = 34; ap = f + 4;  }  // Reassociation Request
  else return;

  if (len < tag + 2 || f[tag] != 0) return;       // tag 0 = SSID
  int sl = f[tag + 1];
  if (sl == 0 || sl > 32 || tag + 2 + sl > len) return;
  if (f[tag + 2] == 0) return;                    // اسم مصفّر (مخفي)

  for (int i = 0; i < revealCount; i++)
    if (memcmp(revealed[i].bssid, ap, 6) == 0) return;
  if (revealCount >= 20) return;

  Reveal& r = revealed[revealCount];
  memcpy(r.bssid, ap, 6);
  memcpy(r.ssid, f + tag + 2, sl);
  r.ssid[sl] = 0;
  revealCount++;
}

// ---------- الاستماع في الخلفية (بدون انتظار) ----------
int sniffIdx = -1;   // الشبكة المخفية التي نستمع لها حالياً

void stopSniff() {
  if (sniffIdx >= 0) {
    esp_wifi_set_promiscuous(false);
    sniffIdx = -1;
  }
}

void startSniff(int i) {
  stopSniff();
  revealCount = 0;

  wifi_promiscuous_filter_t flt;
  flt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&flt);
  esp_wifi_set_promiscuous_rx_cb(&sniffCb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(nets[i].channel, WIFI_SECOND_CHAN_NONE);

  sniffIdx = i;
}

// ---------- فحص الشبكات ----------
void scanNetworks() {
  started = false;
  netCount = 0;
  cur = 0;
  page = 0;

  stopSniff();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Scanning WiFi...");

  WiFi.scanDelete();

  // مسح متزامن: ينتظر حتى ينتهي الفحص
  int found = WiFi.scanNetworks(false, true);
  if (found > 0) {
    for (int i = 0;
         i < found && netCount < MAX_NETS;
         i++) {
      addNet(
        WiFi.SSID(i),
        WiFi.BSSIDstr(i),
        WiFi.RSSI(i),
        WiFi.channel(i),
        WiFi.encryptionType(i)
      );
    }
  }

  WiFi.scanDelete();

  // شبكات تجريبية
  if (DEMO_MODE) {
    addNet("Home_WiFi",
           "AA:BB:CC:11:22:33",
           -50, 1, WIFI_AUTH_WPA2_PSK);

    addNet("Home_WiFi",
           "DE:AD:BE:EF:00:01",
           -28, 6, WIFI_AUTH_OPEN);

    addNet("Free_Airport_WiFi",
           "12:34:56:78:9A:BC",
           -60, 11, WIFI_AUTH_OPEN);

    addNet("",
           "66:77:88:99:AA:BB",
           -70, 3, WIFI_AUTH_WPA2_PSK);

    addNet("OldRouter",
           "22:33:44:55:66:77",
           -75, 9, WIFI_AUTH_WEP);
  }

  analyze();

  // عرض رسالة انتهاء الفحص
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Scan finished");
  lcd.setCursor(0, 1);
  lcd.printf("Found: %d", netCount);

  delay(2000);
}

// ---------- مصابيح LED ----------
void updateLeds() {
  if (netCount == 0 || cur >= netCount) {
    digitalWrite(LED_GREEN, LOW);
    digitalWrite(LED_RED, LOW);
    return;
  }

  bool ok = (nets[cur].level == 0);

  digitalWrite(LED_GREEN, ok ? HIGH : LOW);
  digitalWrite(LED_RED, ok ? LOW : HIGH);
}

// ---------- عرض معلومات الشبكة ----------
void drawPage() {
  lcd.clear();

  if (netCount == 0) {
    lcd.setCursor(0, 0);
    lcd.print("No networks");
    return;
  }

  Net& n = nets[cur];

  const char* lvl =
    (n.level == 0) ? "TRUSTED" :
    (n.level == 1) ? "SUSPECT" : "DANGER";

  lcd.setCursor(0, 0);

  if (n.hidden) {
    if (n.real.length() > 0) {
      lcd.print("*" + n.real.substring(0, 15));   // النجمة = اسم مكشوف
    } else {
      String b = n.bssid;
      b.replace(":", "");
      lcd.print("Hid:" + b);
    }
  } else {
    lcd.print(n.ssid.substring(0, 16));
  }

  lcd.setCursor(0, 1);

  switch (page) {
    case 0:
      lcd.printf("%d/%d [%s]",
                 cur + 1, netCount, lvl);
      break;
      case 1:
      lcd.printf("Risk:%d%% Tr:%d%%",
                 n.risk, 100 - n.risk);
      break;

    case 2:
      lcd.print(n.reason.substring(0, 16));
      break;

    case 3:
      lcd.printf("RSSI:%d CH:%d",
                 n.rssi, n.channel);
      break;

    case 4:
      lcd.printf("%s Hid:%s",
                 encName(n.enc),
                 n.hidden ? "Yes" : "No");
      break;

    case 5: {
      String b = n.bssid;
      b.replace(":", "");
      lcd.print(b.substring(0, 16));
      break;
    }
  }
}

// ---------- عرض الشبكة الحالية ----------
void showNet() {
  if (netCount == 0) {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("No networks");
    digitalWrite(LED_GREEN, LOW);
    digitalWrite(LED_RED, LOW);
    return;
  }

  started = true;

  // شبكة مخفية بدون اسم معروف: استمع في الخلفية، غير ذلك أوقف الاستماع
  if (nets[cur].hidden && nets[cur].real.length() == 0)
    startSniff(cur);
  else
    stopSniff();

  drawPage();
  updateLeds();
}

// ---------- بعد انتهاء الفحص ----------
void showDone() {
  cur = 0;
  page = 0;

  if (netCount > 0) {
    showNet();
  } else {
    started = false;
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("No networks");
    lcd.setCursor(0, 1);
    lcd.print("Press both keys");

    digitalWrite(LED_GREEN, LOW);
    digitalWrite(LED_RED, LOW);
  }
}

// ---------- الأزرار ----------
bool pressed(int pin) {
  if (digitalRead(pin) == LOW) {
    delay(30);
    if (digitalRead(pin) == LOW)
      return true;
  }
  return false;
}

void waitRelease() {
  while (digitalRead(BTN_NEXT) == LOW ||
         digitalRead(BTN_PREV) == LOW) {
    delay(10);
  }
  delay(50);
}

// ترجع true إذا انضغط نفس الزر مرة ثانية خلال DOUBLE_MS
bool secondPress(int pin) {
  unsigned long t = millis();
  while (millis() - t < DOUBLE_MS) {
    if (digitalRead(pin) == LOW) {
      delay(30);
      if (digitalRead(pin) == LOW) return true;
    }
  }
  return false;
}

// عرض معلومات الشبكة الحالية صفحة صفحة (ثانيتين لكل صفحة)
void showInfoPages() {
  for (page = 1; page < 6; page++) {
    drawPage();
    unsigned long t = millis();
    while (millis() - t < 2000) {
      // أي زر ينهي العرض ويرجع للشاشة الرئيسية
      if (digitalRead(BTN_NEXT) == LOW ||
          digitalRead(BTN_PREV) == LOW) {
        waitRelease();
        page = 0;
        drawPage();
        return;
      }
    }
  }
  page = 0;
  drawPage();
}

// ملخص الفحص: العدد الكلي، الموثوقة، وغير الموثوقة
void showSummary() {
  int trusted = 0, untrusted = 0;
  for (int i = 0; i < netCount; i++) {
    if (nets[i].level == 0) trusted++;
    else untrusted++;
  }

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.printf("Scan done: %d", netCount);
  lcd.setCursor(0, 1);
  lcd.printf("Trust:%d Bad:%d", trusted, untrusted);

  // يبقى 5 ثواني أو حتى تضغط أي زر
  unsigned long t = millis();
  while (millis() - t < 5000) {
    if (digitalRead(BTN_NEXT) == LOW ||
        digitalRead(BTN_PREV) == LOW) {
      waitRelease();
      break;
    }
  }
  showNet();
}

// يفحص الحزم الملتقطة، وإذا ظهر الاسم يحدّث الشاشة فوراً
void checkReveal() {
  if (sniffIdx < 0) return;

  Net& n = nets[sniffIdx];

  for (int k = 0; k < revealCount; k++) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
             revealed[k].bssid[0], revealed[k].bssid[1],
             revealed[k].bssid[2], revealed[k].bssid[3],
             revealed[k].bssid[4], revealed[k].bssid[5]);

    if (n.bssid.equalsIgnoreCase(b)) {
      n.real = revealed[k].ssid;
      int idx = sniffIdx;
      stopSniff();
      if (cur == idx) drawPage();
      return;
    }
  }
}

// ---------- الإعداد ----------
void setup() {
  Serial.begin(115200);

  pinMode(BTN_NEXT, INPUT_PULLUP);
  pinMode(BTN_PREV, INPUT_PULLUP);

  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_RED, OUTPUT);

  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED, LOW);

  Wire.begin(26, 32);
  lcd.init();
  lcd.backlight();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // فحص واحد فقط عند التشغيل
  scanNetworks();
  showDone();
}
// ---------- الحلقة الرئيسية ----------
void loop() {
  checkReveal();

  bool next = pressed(BTN_NEXT);
  bool prev = pressed(BTN_PREV);

  // الزران معاً: إعادة الفحص
  if (next && prev) {
    waitRelease();
    scanNetworks();
    showDone();
  }

  // الأخضر: ضغطة = الشبكة التالية، ضغطتين = ملخص الفحص
  else if (next) {
    waitRelease();
    if (netCount > 0) {
      if (secondPress(BTN_NEXT)) {
        waitRelease();
        showSummary();
      } else {
        cur = (cur + 1) % netCount;
        page = 0;
        showNet();
      }
    }
  }

  // الأحمر: ضغطة = الشبكة السابقة، ضغطتين = معلومات الشبكة
  else if (prev) {
    waitRelease();
    if (netCount > 0) {
      if (secondPress(BTN_PREV)) {
        waitRelease();
        showInfoPages();
      } else {
        cur = (cur - 1 + netCount) % netCount;
        page = 0;
        showNet();
      }
    }
  }
}