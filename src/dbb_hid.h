// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBDBB_DBB_HID_H
#define LIBDBB_DBB_HID_H

#include "dbb.h"

#include <stdint.h>
#include <stdlib.h>

#define HID_MAX_BUF_SIZE 5120

struct hid_device_;

/* DBBCommunicationInterfaceHID: A USB HID communication interface
 * Uses libhidapi
 */
class DBBCommunicationInterfaceHID : public DBBCommunicationInterface {
private:
    struct hid_device_* m_HIDHandle;
    unsigned char m_HIDReportBuffer[HID_MAX_BUF_SIZE]; //the USB HID in/out buffer

    // send a command in bootloader mode
    bool sendBootloaderCmd(uint16_t cmd, const std::vector<unsigned char>& data, std::string& resultOut);

    // open a connection to a possible endpoint
    bool openConnectionAtPath(const std::string& devicePath);

public:
    DBBCommunicationInterfaceHID() : m_HIDHandle(nullptr) {}
    bool sendSynchronousJSON(const std::string& json, std::string& result);
    // returns the possible DBBDeviceState (detects if a device is connected and in what mode)
    DBBDeviceState findDevice(std::string& deviceIdentifierOut);
    bool openConnection(const std::string& deviceIdentifier);
    bool closeConnection();
    bool upgradeFirmware(const std::vector<unsigned char>& firmwarePadded, const size_t firmwareSize, const std::string& sigCmpStr, progressCallback progressCB);
};


#endif // LIBDBB_DBB_HID_H
