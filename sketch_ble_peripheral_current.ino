#include <AES.h>
#include <AESLib.h>
#include <AES_config.h>
#include <xbase64.h>
#undef dump

#include <M5Core2.h>
#include <M5Display.h>
#include <Wire.h>
#include "driver/gpio.h"
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>


//#include <BLE2902.h>
#include <JWT_RS256.h>
extern "C" {
  #include "crypto/base64.h"
  
}

JWT_RS256 token_manager;

bool isTokenValid = false;

String jwtToken = "";


// Example sound data (a simple beep sound)
const unsigned char soundData[] = {
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Example sound data (a simple beep sound)
const unsigned char unlockSoundData[] = {
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
  0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x80, 0x3E, 0x00, 0x00,
  0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const char *rsa_public_key = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA729b6ajmBaO7oDL72NkF\n"
"qHJtAEumIO4gorrAai4V7RPReiZ/EX8P2d++9q+F1lKcq+so3UaDzELk8gp9AtVx\n"
"BuQk8G9sLu4QxwM/sPgdz0f8hV3OM603A29XcAv0ztzdV11UYfOXPM1IkzWPCwmV\n"
"MBZpzATrXsQYFGkWe7kwFuz+KgRSAyra/UEdI6iSS3VLUhxVQ3xChO+8VVq9xJpl\n"
"CxXZngbyL9dqY6WRSAocFCiho7VtDY8Rk9gLPLc56pq5J/32F/Uv7tvpGFjL845o\n"
"zGt0LBvoOqIHbWeKza7gVkb6AbY25YLAJaqskc+udRG4KgsXvTovrFkWhYWKWxrp\n"
"0wIDAQAB\n"
"-----END PUBLIC KEY-----";

const size_t soundDataSize = sizeof(soundData);
const size_t unlockSoundDataSize = sizeof(unlockSoundData);

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define UNLOCK_CHARACTERISTIC_UUID "beb5483f-36e1-4688-b7f5-ea07361b26a8"


BLECharacteristic *pCharacteristic;
BLECharacteristic *unlockCharacteristic;

bool deviceConnected = false;
uint32_t value = 0;
BLEServer *pServer;

void playBeep(){
  M5.Spk.PlaySound(soundData, soundDataSize);
}

void playUnlockSound(){
  M5.Spk.PlaySound(unlockSoundData, unlockSoundDataSize);
}


class MyServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      deviceConnected = true;
      M5.Lcd.println("\nDevice Connected");
      Serial.println("\nDevice Connected");
      playBeep();
      delay(200);
      playBeep();
    };

    void onDisconnect(BLEServer* pServer) {
      playBeep();
      deviceConnected = false;
      M5.Lcd.println(F("\nDevice Disconnected"));
      Serial.println("Device Disconnected");
      pServer->getAdvertising()->start();
    }
};



class UnlockCallbacks : public BLECharacteristicCallbacks {
    std::string fullToken = "";  // Buffer to store the concatenated token chunks

    void onWrite(BLECharacteristic *pCharacteristic) override {
        std::string tokenChunk = std::string(pCharacteristic->getValue().c_str());

        if (!tokenChunk.empty()) {
            fullToken += tokenChunk;

            size_t endPos = tokenChunk.find("END_OF_TOKEN");
            if (endPos != std::string::npos) {
                size_t delimiterPos = fullToken.find("END_OF_TOKEN");
                if (delimiterPos != std::string::npos) {
                    fullToken = fullToken.substr(0, delimiterPos);
                }

                String encryptedTokenBase64 = String(fullToken.c_str());
                Serial.println(encryptedTokenBase64);
                Serial.printf("Encrypted Token Length: %d\n", encryptedTokenBase64.length());

                // Decode the Base64-encoded encrypted token
                size_t base64DecodedLength = (encryptedTokenBase64.length() * 3) / 4;
                uint8_t* decryptedData = (uint8_t*)malloc(base64DecodedLength);  // Allocate memory for decrypted data
                if (!decryptedData) {
                    M5.Lcd.println(F("Memory allocation for decryptedData failed."));
                    return;
                }

                unsigned char* decodedToken = base64_decode((const unsigned char*)encryptedTokenBase64.c_str(), encryptedTokenBase64.length(), &base64DecodedLength);

                if (!decodedToken) {
                    M5.Lcd.println(F("Base64 decoding failed for encrypted token."));
                    free(decryptedData);
                    return;
                }

                memcpy(decryptedData, decodedToken, base64DecodedLength);

                Serial.println("Base64 Decoded Token (Hexadecimal):");
for (size_t i = 0; i < base64DecodedLength; i++) {
    Serial.printf("%02X ", decodedToken[i]);
}
Serial.println();

// Optionally, print as string if data is textual
//Serial.println("Base64 Decoded Token (String):");
//Serial.println((char*)decodedToken);
                free(decodedToken);  // Free the allocated memory for decodedToken

                Serial.printf("Base64 Decoded Length: %d\n", base64DecodedLength);

                // Decode the AES key
                String base64EncodedKey = "YW5vdGhlcmN1c3RvbWNsYWltYWRkZWR0b2lkdG9rZW4=";
                size_t keyLength = (base64EncodedKey.length() * 3) / 4;
                uint8_t aesKey[keyLength];

                unsigned char* decodedKey = base64_decode((const unsigned char*)base64EncodedKey.c_str(), base64EncodedKey.length(), &keyLength);
               
                if (!decodedKey) {
                    M5.Lcd.println(F("Base64 decoding failed for AES key."));
                    free(decryptedData);
                    return;
                }

                memcpy(aesKey, decodedKey, keyLength);
                Serial.println("AES Key:");
for (size_t i = 0; i < keyLength; i++) {
    Serial.printf("%02X ", aesKey[i]);  // Print each byte as a hexadecimal value
}
Serial.println();


                free(decodedKey);  // Free the allocated memory for decodedKey

                if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
                    M5.Lcd.println(F("Invalid AES key length."));
                    free(decryptedData);
                    return;
                }

                AES aesLib;
                aesLib.set_key(aesKey, keyLength);
                Serial.println("AES key set successfully.");

                size_t paddingLength = base64DecodedLength % 16;
                if (paddingLength != 0) {
                    size_t newLength = base64DecodedLength + (16 - paddingLength);
                    uint8_t* paddedData = (uint8_t*)malloc(newLength);
                    memset(paddedData, 0, newLength);  // Clear the padded data
                    memcpy(paddedData, decryptedData, base64DecodedLength);  // Copy existing data into paddedData

                    free(decryptedData);  // Free the original data
                    decryptedData = paddedData;  // Update decryptedData pointer

                    base64DecodedLength = newLength;  // Update the length after padding
                }

                uint8_t* encryptedToken = decryptedData;  // Use pointer if necessary
                // Or if encryptedToken must be an array:
                // uint8_t encryptedToken[base64DecodedLength];  // Allocate a fixed-size array
                // memcpy(encryptedToken, decryptedData, base64DecodedLength);  // Copy padded data into the array

                // Decrypt the encrypted token
                uint8_t* tempBuffer = (uint8_t*)malloc(16);  // Allocate buffer of 16 bytes

                for (size_t i = 0; i < base64DecodedLength; i += 16) {
                    memcpy(tempBuffer, decryptedData + i, 16);  // Copy the current 16-byte block into tempBuffer
                    aesLib.decrypt(tempBuffer, decryptedData + i);  // Pass tempBuffer as plain and store the result in decryptedData
                    memcpy(decryptedData + i, tempBuffer, 16);  // Copy back the decrypted data from tempBuffer
                }

                free(tempBuffer);

              Serial.println("Decrypted Value (Before Padding Removal):");
for (size_t i = 0; i < base64DecodedLength; i++) {
    Serial.printf("%02X ", decryptedData[i]);  // Print in hexadecimal
}
Serial.println();
//Serial.println((char*)decryptedData);
                
                uint8_t paddingValue = decryptedData[base64DecodedLength - 1];
                if (paddingValue < 1 || paddingValue > 16) {
                    Serial.println("Invalid padding value detected!");
                    Serial.printf("Padding Value: %u\n", paddingValue);
                    free(decryptedData);
                    return;
                }

                // Check padding bytes
                for (size_t i = 0; i < paddingValue; ++i) {
                    if (decryptedData[base64DecodedLength - 1 - i] != paddingValue) {
                        Serial.println("Invalid padding detected!");
                        free(decryptedData);
                        return;
                    }
                }

                size_t decryptedLength = base64DecodedLength - paddingValue;
                char decryptedToken[decryptedLength + 1];
                memcpy(decryptedToken, decryptedData, decryptedLength);
                decryptedToken[decryptedLength] = '\0';
                free(decryptedData);

                Serial.println("Padding successfully removed.");
                Serial.print("Decrypted Token: ");
                Serial.println(decryptedToken);

                M5.Lcd.println(F("Decrypted ID Token:"));
                M5.Lcd.println(decryptedToken);

                // Validate the token
                String jwtToken = String(decryptedToken);
                if (token_manager.tokenIsValid(jwtToken)) {
                    M5.Lcd.println(F("Valid Token! Unlocking..."));
                } else {
                    M5.Lcd.println(F("Invalid Token."));
                }

                // Reset fullToken buffer
                fullToken = "";
            }
        } else {
            M5.Lcd.println(F("Received empty token chunk."));
        }
    }
};










void setup() {
  M5.begin();
  Serial.begin(115200);




  // Initialize BLE
  BLEDevice::init("M5Stack Core2 BLE Reader");
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  // Create BLE Service
  BLEService *pService = pServer->createService(SERVICE_UUID);

  // Create BLE Characteristic
  pCharacteristic = pService->createCharacteristic(
                      CHARACTERISTIC_UUID,
                      BLECharacteristic::PROPERTY_READ |
                      BLECharacteristic::PROPERTY_WRITE
                    );

  //pCharacteristic->addDescriptor(new BLE2902());

  // Create BLE Characteristic
  unlockCharacteristic = pService->createCharacteristic(
                          UNLOCK_CHARACTERISTIC_UUID,
                          BLECharacteristic::PROPERTY_READ |
                          BLECharacteristic::PROPERTY_WRITE
                          );

  unlockCharacteristic->setCallbacks(new UnlockCallbacks());

 
  // Start the service
  pService->start();

  // Start advertising
  pServer->getAdvertising()->start();

  token_manager.rsa_public_key = (char*)rsa_public_key;
  M5.Lcd.print(F("Waiting for a BLE client to connect....."));
  Serial.println("Waiting for a BLE client to connect.....");
  
}

void loop() {
  //  delay(1000); // Send new value every second
  //  if (deviceConnected) {
  //    pCharacteristic->setValue(value);
  //   pCharacteristic->notify();
  //    value++;
  //  }
   //else{
     //M5.Lcd.print("\nDevice disconnected");
   //}
  

  
  }




