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

#define FIRMWARE_SIGLEN (7*64) //7 concatenated signatures
#define DBB_FIRMWARE_LENGTH 225280 //flash size minus bootloader length
#define FIRMWARE_CHUNKSIZE 4096

typedef std::function<void(float progress)> progressCallback;

/* DBBCommunicationInterface abstract communication interface
 *
 */
class DBBCommunicationInterface {
public:

    virtual ~DBBCommunicationInterface() {}

    virtual bool openConnection() =0;
    virtual bool closeConnection() =0;
    virtual bool sendSynchronousJSON(const std::string& json, std::string& result) =0;

    virtual bool upgradeFirmware(const std::vector<unsigned char>& firmwarePadded, const size_t firmwareSize, const std::string& sigCmpStr, progressCallback progressCB) =0;
};

enum class DBBDeviceState {NoDevice, Firmware, FirmwareUninitialized, Bootloader, FirmwareToOldAndUnsupported};
class DBB
{
    /* callback function once a command has been executed */
    typedef std::function<void(const std::string& result, int status)> commandCallback;

    /* command package for the queue, json and callback */
    typedef std::pair<const std::string, commandCallback> commandPackage;

private:
    mutable std::mutex m_comLock;

    std::atomic<bool> m_stopCheckThread;
    std::atomic<bool> m_pauseCheckThread;
    std::atomic<bool> m_stopExecuteThread;

    /* the command execution queue */
    SafeQueue<commandPackage> threadQueue;

    /* device check thread */
    std::thread m_usbCheckThread;

    /* device command dispatching thread */
    std::thread m_usbExecuteThread;

    /* communication interface */
    std::unique_ptr<DBBCommunicationInterface> comInterface;

    bool encryptAndEncode(const std::string& json, const std::string& passphrase, std::string& base64out);
    bool decodeAndDecrypt(const std::string& base64Ciphertext, const std::string& passphrase, std::string& encodeOut);

public:

    DBB();
    ~DBB();

    /* dispatch a command
     * The communication will happen on the execution thread
     * The callback will be called via the execution thread
     */
    bool sendCommand(const std::string& json, const std::string& passphrase, std::string& result, commandCallback callback, bool encrypt = true);
    bool upgradeFirmware(const std::string& filename);
};

#endif // LIBDBB_DBB_H
