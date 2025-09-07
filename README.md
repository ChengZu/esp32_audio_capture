# ESP32s3 音频采集

pcm1808采集声音，网页播放录制，pcm5102也进行播放

## Hardware Setup

### Required Components
- ESP32s3 Development Board
- PCM1808 ADC Module
- PCM5102 DAC Module
- Audio Input Source (microphone, line-in, etc.)
- Audio Output (speakers, headphones, etc.)
- Jumper Wires

### Connections
```
ESP32s3  ->   PCM1808 (ADC)
GPIO4    ->   WS      (Word Select/LRCLK)
GPIO5    ->   DOUT    (Data Output)
GPIO6    ->   BCK     (Bit Clock)
3.3V     ->   VCC
GND      ->   GND

ESP32s3  ->   PCM5102 (DAC)
GPIO16   ->   LCK     (Left/Right Clock)
GPIO17   ->   DIN     (Data Input)
GPIO18   ->   BCK     (Bit Clock)
3.3V     ->   VCC
GND      ->   GND

### License

This project is open source and available under the MIT License.
