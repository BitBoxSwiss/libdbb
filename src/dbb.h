// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBDBB_DBB_H
#define LIBDBB_DBB_H

#include "safequeue.h"

#include <stdint.h>
#include <stdlib.h>

#include <crypto/sha256.h>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

#define FIRMWARE_SIGLEN (7 * 64)   //7 concatenated signatures
#define DBB_FIRMWARE_LENGTH 225280 //flash size minus bootloader length
#define FIRMWARE_CHUNKSIZE 4096

typedef std::function<void(float progress)> progressCallback;

/* ENUMs for the possible device states */
enum class DBBDeviceState {
    NoDevice,
    Firmware,
    FirmwareUninitialized,
    Bootloader,
    FirmwareToOldAndUnsupported
};

/* DBBCommunicationInterface abstract communication interface
 *
 * TODO: add a way to select a device if multiple are connected
 */
class DBBCommunicationInterface
{
public:
    virtual ~DBBCommunicationInterface() {}

    /* Detects if a DigitalBitbox device is available and returns the possible DBBDeviceState
     * deviceIdentifierOut will be populated if a device has been found
     * INFO: deviceIdentifierOut is for future multidevice useage
     */
    virtual DBBDeviceState findDevice(std::string& deviceIdentifierOut) = 0;

    /* open a connection to the primary device
     * If the deviceIdentifier is unset or empty, the communication interface will then
     * try to connect to the primary available device
     * INFO: deviceIdentifierOut is for future multidevice useage
     */
    virtual bool openConnection(const std::string& deviceIdentifier) = 0;

    // close current connection
    virtual bool closeConnection() = 0;

    // send JSON to the device
    virtual bool sendSynchronousJSON(const std::string& json, std::string& result) = 0;

    // upgrade firmware with data blob
    virtual bool upgradeFirmware(const std::vector<unsigned char>& firmwarePadded, const size_t firmwareSize, const std::string& sigCmpStr, progressCallback progressCB) = 0;
};

class DBBDeviceManager
{
    /* callback function once a command has been executed */
    typedef std::function<void(const std::string& result, int status)> commandCallback;

    /* callback function once the device state has changed */
    typedef std::function<void(const DBBDeviceState, const std::string& deviceIdentifier)> deviceStateChangedCallback;

    /* command package for the queue, json and callback */
    typedef std::pair<const std::string, commandCallback> commandPackage;

private:
    mutable std::mutex m_comLock; //!< lock for the communication interface

    std::atomic<bool> m_stopCheckThread;
    std::atomic<bool> m_pauseCheckThread;
    std::atomic<bool> m_stopExecuteThread;

    /* Find device state change callback */
    deviceStateChangedCallback m_deviceChanged;

    /* the command execution queue */
    SafeQueue<commandPackage> m_threadQueue;

    /* device check thread */
    std::thread m_usbCheckThread;

    /* device command dispatching thread */
    std::thread m_usbExecuteThread;

    /* communication interface */
    std::unique_ptr<DBBCommunicationInterface> m_comInterface;

    bool encryptAndEncode(const std::string& json, const std::string& passphrase, std::string& base64out);
    bool decodeAndDecrypt(const std::string& base64Ciphertext, const std::string& passphrase, std::string& encodeOut);

public:
    /*
     * instantiate a new device interaction manager
     * Be aware that the callbacks are called on either the usbCheckThread or the usbExecutionThread
     */
    DBBDeviceManager(deviceStateChangedCallback stateChangeCallbackIn);
    ~DBBDeviceManager();

    /* dispatch a command
     * The communication will happen on the execution thread
     * The callback will be called via the execution thread
     */
    bool sendCommand(const std::string& json, const std::string& passphrase, std::string& result, commandCallback callback, bool encrypt = true);

    /* try to upgrade firmware, will require a device in DBBDeviceState::Bootloader state
     * developmentDevice      (set to true if you want to upgrade the firmware on a development device
     * developmentSignature   (if not a nullptr, this ECDSA secp256k1 compact signature (64 bytes) will be applied
     *                         works only on development devices)
     */
    bool upgradeFirmware(const std::string& filename, bool developmentDevice = false, std::string* developmentSignature = nullptr);

    /* looks for a possible DigitalBitbox device to connect to */
    DBBDeviceState findDevice(std::string& deviceIdentifierOut);
};

#endif // LIBDBB_DBB_H
