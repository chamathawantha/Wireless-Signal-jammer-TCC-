#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <WiFi.h>
#include <WiFiServer.h>
#include <vector>
#include <Arduino.h>

// --- PCAP Structures ---
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// --- External Variables ---
// These are defined in your main file.
extern struct HandshakeData capturedHandshake;
extern struct ManagementData capturedManagement;

// Minimal Radiotap header (8 bytes)
const uint8_t minimal_rtap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};

// --- Function to generate the PCAP data in memory ---
std::vector<uint8_t> generatePcapBuffer() {
  std::vector<uint8_t> pcapData;

  // Build and append the global header.
  PcapGlobalHeader gh;
  gh.magic_number = 0xa1b2c3d4; // Little-endian magic number
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 127; // DLT_IEEE802_11_RADIO

  uint8_t* ghPtr = (uint8_t*)&gh;
  for (size_t i = 0; i < sizeof(gh); i++) {
    pcapData.push_back(ghPtr[i]);
  }

  // Helper lambda to write one packet.
  auto writePacket = [&](const uint8_t* packetData, size_t packetLength) {
    PcapPacketHeader ph;
    unsigned long ms = millis();
    ph.ts_sec = ms / 1000;
    ph.ts_usec = (ms % 1000) * 1000;
    ph.incl_len = packetLength + sizeof(minimal_rtap);
    ph.orig_len = packetLength + sizeof(minimal_rtap);

    uint8_t* phPtr = (uint8_t*)&ph;
    for (size_t i = 0; i < sizeof(ph); i++) {
      pcapData.push_back(phPtr[i]);
    }
    // Append Radiotap header.
    for (size_t i = 0; i < sizeof(minimal_rtap); i++) {
      pcapData.push_back(minimal_rtap[i]);
    }
    // Append packet data.
    for (size_t i = 0; i < packetLength; i++) {
      pcapData.push_back(packetData[i]);
    }
  };

  // Write handshake frames.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    writePacket(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length);
  }
  // Write management frames.
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    writePacket(capturedManagement.frames[i].data, capturedManagement.frames[i].length);
  }
  
  return pcapData;
}

// --- Function to Start the Webserver ---
// This function starts an HTTP server on port 80 and waits for valid GET requests to serve the PCAP file.
void startWebServer() {
  // Create a WiFi server on port 80.
  WiFiServer server(80);
  server.begin();
  Serial.println("Web server started on port 80.");

    display.setCursor(5, 22);
    display.print("Conneact to 0x7359");
    display.setCursor(5, 34);
    display.println("Download pcap from");
    display.setCursor(5, 46);
    display.print("http://");
    display.print(WiFi.localIP());

  // Generate the PCAP data once.
  std::vector<uint8_t> pcapData = generatePcapBuffer();
  Serial.print("PCAP size: ");
  Serial.print(pcapData.size());
  Serial.println(" bytes");

  // Main server loop.
  while (true) {
    if (digitalRead(BTN_OK) == LOW) {
      Serial.println("BTN_OK pressed. Exiting webserver mode.");
      break;
    }

    WiFiClient client = server.available();
    if (client) {
      Serial.println("Client connected.");
      // Wait up to 5 seconds for client request data.
      unsigned long reqTimeout = millis();
      while (!client.available() && (millis() - reqTimeout < 1000)) {
        delay(10);
      }
      
      // Read the first line of the request.
      String req = client.readStringUntil('\n');
      req.trim();
      Serial.print("Request: ");
      Serial.println(req);
      
      // If the request doesn't start with "GET", send a 400 response.
      if (!req.startsWith("GET")) {
        client.println("HTTP/1.1 400 Bad Request");
        client.println("Connection: close");
        client.println();
        client.stop();
        Serial.println("Bad request; client disconnected.");
        continue;
      }
      
      // Send HTTP headers.
      client.println("HTTP/1.1 200 OK");
      client.println("Content-Type: application/octet-stream");
      client.println("Content-Disposition: attachment; filename=\"capture.pcap\"");
      client.println("Connection: close");
      client.println();
      
      // Send the raw PCAP data.
      for (size_t i = 0; i < pcapData.size(); i++) {
        client.write(pcapData[i]);
      }
      
      delay(1);
      client.stop();
      Serial.println("Client disconnected, PCAP served.");
    }
    delay(10);
  }
}

#endif  // WEBSERVER_H
