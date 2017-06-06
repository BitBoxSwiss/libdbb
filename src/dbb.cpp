// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbb.h"

#include "crypto/aes.h"
#include "crypto/random.h"
#include "dbb_hid.h"
#include "support/cleanse.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include "univalue.h"

#include <fstream>
#include <iostream>
#include <time.h>


const static int FIND_DEVICE_POLL_INTERVAL_IN_MS = 1000;
DBB::~DBB()
{
    m_stopCheckThread = true;
    m_stopExecuteThread = true;
    m_usbCheckThread.join();
    m_usbExecuteThread.join();
    printf("stop...\n");
}

DBB::DBB(deviceStateChangedCallback stateChangeCallbackIn) : m_stopCheckThread(false), m_pauseCheckThread(false), m_stopExecuteThread(false), m_deviceChanged(stateChangeCallbackIn)
{
    // for now, always use the HID communcation interface
    m_comInterface = std::unique_ptr<DBBCommunicationInterface>(new DBBCommunicationInterfaceHID());

    // dispatch the USB check thread
    m_usbCheckThread = std::thread([&]() {
        DBBDeviceState currentDeviceState = DBBDeviceState::NoDevice;
        while (!m_stopCheckThread) {
            if (!m_pauseCheckThread) {
                DBBDeviceState state;
                std::string possibleDeviceIdentifier;
                {
                    std::lock_guard<std::mutex> lock(m_comLock);
                    state = m_comInterface->findDevice(possibleDeviceIdentifier);
                }
                if (currentDeviceState != state) {
                    // device state has changed, inform via callback
                    m_deviceChanged(state, possibleDeviceIdentifier);
                    currentDeviceState = state;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(FIND_DEVICE_POLL_INTERVAL_IN_MS));
        }
    });

    // dispatch the execution thread
    m_usbExecuteThread = std::thread([&]() {

        // loop unless shutdown has been requested and queue is empty
        while (!m_stopExecuteThread || m_threadQueue.size() > 0) {
            // dequeue a execution package
            commandPackage cmdCB = m_threadQueue.dequeue();

            std::string result;

            // open a connection, send command and close connection
            bool res;
            {
                std::lock_guard<std::mutex> lock(m_comLock);
                m_comInterface->openConnection(std::string());
                res = m_comInterface->sendSynchronousJSON(cmdCB.first, result);
                m_comInterface->closeConnection();
            }

            // call callback with result
            cmdCB.second(result, res ? 1 : 0);
        }
    });
}

bool DBB::decodeAndDecrypt(const std::string& base64Ciphertext, const std::string& passphrase, std::string& plaintextOut)
{
    if (base64Ciphertext.empty() || passphrase.empty())
        return false;

    std::string ciphertext = DecodeBase64(base64Ciphertext);
    uint256 passphraseHash;
    Hash256().Write((unsigned char*)passphrase.data(), passphrase.size()).Finalize(passphraseHash.begin());

    plaintextOut.resize(ciphertext.size() - AES_BLOCKSIZE);

    AES256CBCDecrypt dec(passphraseHash.begin(), reinterpret_cast<const unsigned char*>(&ciphertext[0]) /* pass IV via cipertext buffer */, true);
    int size = dec.Decrypt(reinterpret_cast<const unsigned char*>(&ciphertext[0] + AES_BLOCKSIZE), ciphertext.size() - AES_BLOCKSIZE, reinterpret_cast<unsigned char*>(&plaintextOut[0]));
    plaintextOut.resize(size);

    memory_cleanse(passphraseHash.begin(), passphraseHash.size());

    return (size > 0);
}

bool DBB::encryptAndEncode(const std::string& json, const std::string& passphrase, std::string& encodeOut)
{
    if (passphrase.empty())
        return false;

    // KDF: use a double sha256 stretching
    // KDF strengt doesn't matter that much because the maximal
    // amount of attempts before the device gets erases is 15
    uint256 passphraseHash;
    Hash256().Write((unsigned char*)passphrase.data(), passphrase.size()).Finalize(passphraseHash.begin());

    // create output buffer
    std::vector<unsigned char> ciphertext(json.size() + AES_BLOCKSIZE + AES_BLOCKSIZE); // ensure space for the IV

    // prefill the IV in front of the buffer
    GetRandBytes(&ciphertext[0], AES_BLOCKSIZE);

    // encrypt the json and write it to the buffer after the IV
    AES256CBCEncrypt enc(passphraseHash.begin(), &ciphertext[0] /* pass IV via cipertext buffer */, true);
    int size = enc.Encrypt(reinterpret_cast<const unsigned char*>(&json[0]), json.size(), &ciphertext[0] + AES_BLOCKSIZE);

    // resize the buffer, make sure we respect the IV space
    ciphertext.resize(size + AES_BLOCKSIZE);

    // base64 encoding
    encodeOut = EncodeBase64(&ciphertext[0], ciphertext.size());

    memory_cleanse(&ciphertext[0], ciphertext.size());
    memory_cleanse(passphraseHash.begin(), passphraseHash.size());

    return true;
}

bool DBB::sendCommand(const std::string& json, const std::string& passphrase, std::string& result, commandCallback callback, bool encrypt)
{
    std::string textToSend = json;
    if (encrypt) {
        encryptAndEncode(json, passphrase, textToSend);
    }
    m_threadQueue.enqueue(commandPackage(textToSend, [this, passphrase, callback](const std::string& result, int status) {
        // parse result and try to decrypt
        std::string valueToPass = result;
        UniValue resultParsed;
        if (resultParsed.read(result)) {
            UniValue ctext = find_value(resultParsed, "ciphertext");
            if (ctext.isStr()) {
                // seems to be encrypted
                valueToPass = ctext.get_str();
                std::string decodedAndDecrypted;
                if (decodeAndDecrypt(valueToPass, passphrase, decodedAndDecrypted)) {
                    valueToPass = decodedAndDecrypted;
                }
            }
        }
        callback(valueToPass, status);
    }));
    return true;
}

bool DBB::upgradeFirmware(const std::string& filename)
{
    // load file
    bool res = false;
    std::ifstream firmwareFile(filename, std::ios::binary | std::ios::ate);
    std::streamsize firmwareSize = firmwareFile.tellg();
    if (firmwareSize <= 0) {
        return res;
    }
    std::string sigStr;
    firmwareFile.seekg(0, std::ios::beg);

    //read signatures
    unsigned char sigByte[FIRMWARE_SIGLEN];
    firmwareFile.read((char*)&sigByte[0], FIRMWARE_SIGLEN);
    sigStr = HexStr(sigByte, sigByte + FIRMWARE_SIGLEN);

    //read firmware
    std::vector<unsigned char> firmwareBuffer(DBB_FIRMWARE_LENGTH);
    unsigned int pos = 0;
    while (true) {
        firmwareFile.read(reinterpret_cast<char*>(&firmwareBuffer[0] + pos), FIRMWARE_CHUNKSIZE);
        std::streamsize bytes = firmwareFile.gcount();
        if (bytes == 0)
            break;

        pos += bytes;
    }
    firmwareFile.close();

    // append 0xff to the rest of the firmware buffer
    memset((void*)(&firmwareBuffer[0] + pos), 0xff, DBB_FIRMWARE_LENGTH - pos);
    {
        std::lock_guard<std::mutex> lock(m_comLock);
        m_pauseCheckThread = true;
        res = m_comInterface->upgradeFirmware(firmwareBuffer, firmwareSize, sigStr, [](float progress) {
            printf("Upgrade firmware: %.2f%%\n", progress);
        });
        m_pauseCheckThread = false;
    }
    return res;
}
