# Wireless-Signal-jammer-TCC-
<img width="4032" height="3024" alt="device1" src="https://github.com/user-attachments/assets/ac658274-0ab2-4f81-ad2f-660fc9feb5a5" />

# How to Upload Firmware / Usage
1) Go to RTL8720DN_SSD1306_FIX folder. You need to first backup any files that will be replaced, and then add this into your Arduino/libraries folder.
    - This fixes bugs that make Adafruit SSD1306 library incompatible with BW16 board.
2) Upload the firmware using the .ino file via Arduino IDE.
3) Turn it on and select/attack!
4) Credentials to connect to the network to download the .pcap file
    wifi=0x7359
    pw=0123456789


## Requirements

- SSD1306
- 3 Buttons
- BW16 Board (DO NOT USE BW16E, 5GHZ DOESN'T WORK PROPERLY WITH IT)

## Connections

### Buttons
- **Up Button**: PA27  
- **Down Button**: PA12  
- **Select Button**: PA13  

### SSD1306 128x64 .96inch Display
- **SDA**: PA26  
- **SCL**: PA25

## TODO
- [x] signal strength indicator
- [x] web server to serve the captured .pcap files
- [x] battery level display
- [ ] add module to save .pcap file to SD card
- [ ] manage more than one .pcap file per session
- [x] fix display bug after finishing sniffing
- [ ] attack all  + sniff all
- [ ] dual frequency attack on selecting network
- [ ] improve UX/UI
- [ ] refactor the code
- [ ] add evil twin functionality
- [ ] add evil portal functionality
