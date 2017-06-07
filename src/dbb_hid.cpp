// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbb_hid.h"

#include "hidapi/hidapi.h"

#include "compat.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <fstream>
#include <iostream>
#include <math.h>
#include <string.h>

#define HID_READ_TIMEOUT (120 * 1000)
#define HID_MAX_BUF_SIZE 5120
#define HID_BL_BUF_SIZE_W 4098
#define HID_BL_BUF_SIZE_R 256

#define USB_REPORT_SIZE 64
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif


#define HWW_CID 0xff000000

#define TYPE_MASK 0x80 // Frame type mask
#define TYPE_INIT 0x80 // Initial frame identifier
#define TYPE_CONT 0x00 // Continuation frame identifier

#define ERR_INVALID_SEQ 0x04 // Invalid message sequencing

#define U2FHID_ERROR (TYPE_INIT | 0x3f)          // Error response
#define U2FHID_VENDOR_FIRST (TYPE_INIT | 0x40)   // First vendor defined command
#define HWW_COMMAND (U2FHID_VENDOR_FIRST + 0x01) // Hardware wallet command

#define FRAME_TYPE(f) ((f).type & TYPE_MASK)
#define FRAME_CMD(f) ((f).init.cmd & ~TYPE_MASK)
#define MSG_LEN(f) (((f).init.bcnth << 8) + (f).init.bcntl)
#define FRAME_SEQ(f) ((f).cont.seq & ~TYPE_MASK)

__extension__ typedef struct {
    uint32_t cid; // Channel identifier
    union {
        uint8_t type; // Frame type - bit 7 defines type
        struct {
            uint8_t cmd;                       // Command - bit 7 set
            uint8_t bcnth;                     // Message byte count - high
            uint8_t bcntl;                     // Message byte count - low
            uint8_t data[USB_REPORT_SIZE - 7]; // Data payload
        } init;
        struct {
            uint8_t seq;                       // Sequence number - bit 7 cleared
            uint8_t data[USB_REPORT_SIZE - 5]; // Data payload
        } cont;
    };
} USB_FRAME;

static int api_hid_send_frame(hid_device* hid_handle, USB_FRAME* f)
{
    int res = 0;
    uint8_t d[sizeof(USB_FRAME) + 1];
    memset(d, 0, sizeof(d));
    d[0] = 0;               // un-numbered report
    f->cid = htonl(f->cid); // cid is in network order on the wire
    memcpy(d + 1, f, sizeof(USB_FRAME));
    f->cid = ntohl(f->cid);

    res = hid_write(hid_handle, d, sizeof(d));

    if (res == sizeof(d)) {
        return 0;
    }
    return 1;
}


static int api_hid_send_frames(hid_device* hid_handle, uint32_t cid, uint8_t cmd, const void* data, size_t size)
{
    USB_FRAME frame;
    int res;
    size_t frameLen;
    uint8_t seq = 0;
    const uint8_t* pData = (const uint8_t*)data;

    frame.cid = cid;
    frame.init.cmd = TYPE_INIT | cmd;
    frame.init.bcnth = (size >> 8) & 255;
    frame.init.bcntl = (size & 255);

    frameLen = MIN(size, sizeof(frame.init.data));
    memset(frame.init.data, 0xEE, sizeof(frame.init.data));
    memcpy(frame.init.data, pData, frameLen);

    do {
        res = api_hid_send_frame(hid_handle, &frame);
        if (res != 0) {
            return res;
        }

        size -= frameLen;
        pData += frameLen;

        frame.cont.seq = seq++;
        frameLen = MIN(size, sizeof(frame.cont.data));
        memset(frame.cont.data, 0xEE, sizeof(frame.cont.data));
        memcpy(frame.cont.data, pData, frameLen);
    } while (size);

    return 0;
}


static int api_hid_read_frame(hid_device* hid_handle, USB_FRAME* r)
{
    memset((int8_t*)r, 0xEE, sizeof(USB_FRAME));

    int res = 0;
    res = hid_read_timeout(hid_handle, (uint8_t*)r, sizeof(USB_FRAME), HID_READ_TIMEOUT);

    if (res == sizeof(USB_FRAME)) {
        r->cid = ntohl(r->cid);
        return 0;
    }
    return 1;
}


static int api_hid_read_frames(hid_device* hid_handle, uint32_t cid, uint8_t cmd, void* data, int max)
{
    USB_FRAME frame;
    int res, result;
    size_t totalLen, frameLen;
    uint8_t seq = 0;
    uint8_t* pData = (uint8_t*)data;

    (void)cmd;

    do {
        res = api_hid_read_frame(hid_handle, &frame);
        if (res != 0) {
            return res;
        }

    } while (frame.cid != cid || FRAME_TYPE(frame) != TYPE_INIT);

    if (frame.init.cmd == U2FHID_ERROR) {
        return -frame.init.data[0];
    }

    totalLen = MIN(max, MSG_LEN(frame));
    frameLen = MIN(sizeof(frame.init.data), totalLen);

    result = totalLen;

    memcpy(pData, frame.init.data, frameLen);
    totalLen -= frameLen;
    pData += frameLen;

    while (totalLen) {
        res = api_hid_read_frame(hid_handle, &frame);
        if (res != 0) {
            return res;
        }

        if (frame.cid != cid) {
            continue;
        }
        if (FRAME_TYPE(frame) != TYPE_CONT) {
            return -ERR_INVALID_SEQ;
        }
        if (FRAME_SEQ(frame) != seq++) {
            return -ERR_INVALID_SEQ;
        }

        frameLen = MIN(sizeof(frame.cont.data), totalLen);

        memcpy(pData, frame.cont.data, frameLen);
        totalLen -= frameLen;
        pData += frameLen;
    }

    return result;
}

bool DBBCommunicationInterfaceHID::closeConnection()
{
    if (m_HIDHandle) {
        DBB_DEBUG("   [HID CLOSE] closing connection\n");
        hid_close(m_HIDHandle); //vendor-id, product-id
        m_HIDHandle = nullptr;
        hid_exit();
        return true;
    }
    return false;
}

bool DBBCommunicationInterfaceHID::openConnection(const std::string& deviceIdentifier)
{
    return openConnectionAtPath(deviceIdentifier);
}

DBBDeviceState DBBCommunicationInterfaceHID::findDevice(std::string& devicePathOut)
{
    struct hid_device_info *devs, *cur_dev;

    DBB_DEBUG("   [HID] call hid enumerate\n");
    devs = hid_enumerate(0x03eb, 0x2402);

    cur_dev = devs;
    DBBDeviceState state = DBBDeviceState::NoDevice;
    while (cur_dev) {
        DBB_DEBUG("   [HID ENUM] found device (%d, %d)\n", cur_dev->interface_number, cur_dev->usage_page);
        if (cur_dev->interface_number == 0 || cur_dev->usage_page == 0xffff) {
            // get the manufacturer wide string
            if (!cur_dev || !cur_dev->manufacturer_string || !cur_dev->serial_number || !cur_dev->path) {
                cur_dev = cur_dev->next;
                continue;
            }
            devicePathOut.resize(strlen(cur_dev->path));
            devicePathOut.assign(cur_dev->path);
            std::wstring wsMF(cur_dev->manufacturer_string);
            std::string strMF(wsMF.begin(), wsMF.end());

            // get the setial number wide string
            std::wstring wsSN(cur_dev->serial_number);
            std::string strSN(wsSN.begin(), wsSN.end());

            std::vector<std::string> vSNParts = str_split(strSN, ':');

            DBB_DEBUG("   [HID ENUM] Found device with SN: %s\n", strSN.c_str());
            if ((vSNParts.size() == 2 && vSNParts[0] == "dbb.fw") || strSN == "firmware") {
                state = DBBDeviceState::Firmware;
                // for now, only support one digit version numbers
                if (vSNParts[1].size() >= 6 && vSNParts[1][0] == 'v') {
                    int major = vSNParts[1][1] - '0';
                    int minor = vSNParts[1][3] - '0';
                    // UNUSED // int patch = vSNParts[1][5] - '0';

                    // Support firmware >=2.1.0
                    if (major < 2 || (major == 2 && minor < 1)) {
                        state = DBBDeviceState::FirmwareToOldAndUnsupported;
                    }
                }
                if (vSNParts[1].size() > 2 && vSNParts[1][vSNParts[1].size() - 2] == '-' && vSNParts[1][vSNParts[1].size() - 1] == '-') {
                    state = DBBDeviceState::FirmwareUninitialized;
                }
                break;
            } else if (vSNParts.size() == 2 && vSNParts[0] == "dbb.bl") {
                state = DBBDeviceState::Bootloader;
                break;
            } else {
                cur_dev = cur_dev->next;
            }
        } else {
            cur_dev = cur_dev->next;
        }
    }
    hid_free_enumeration(devs);

    return state;
}

bool DBBCommunicationInterfaceHID::openConnectionAtPath(const std::string& devicePath)
{
    std::string pathToCheck = devicePath;
    if (devicePath.empty() || devicePath == "") {
        // find and select a possible device

        DBB_DEBUG("   [HID OPEN CONN] no device path given, looking for device...\n");
        std::string possibleDevicePath;
        if (findDevice(possibleDevicePath) == DBBDeviceState::Firmware) {
            DBB_DEBUG("   [HID OPEN CONN] Bitbox in firmware mode found...\n");
            pathToCheck = possibleDevicePath;
        }
    }
    if (m_HIDHandle) {
        DBB_DEBUG("   [HID OPEN CONN] close old connection\n");
        hid_close(m_HIDHandle); //vendor-id, product-id
        m_HIDHandle = nullptr;
    }
    DBB_DEBUG("   [HID OPEN CONN] open connection to path %s\n", pathToCheck.c_str());
    m_HIDHandle = hid_open_path(pathToCheck.c_str());
    return (m_HIDHandle != nullptr);
}

bool DBBCommunicationInterfaceHID::sendSynchronousJSON(const std::string& json, std::string& result)
{
    if (!m_HIDHandle) {
        return false;
    }

    memset(m_HIDReportBuffer, 0, HID_MAX_BUF_SIZE);
    if (json.size() + 1 > HID_MAX_BUF_SIZE) {
        return false;
    }

    int reportShift = 0;
#ifdef DBB_ENABLE_HID_REPORT_SHIFT
    reportShift = 1;
#endif
    m_HIDReportBuffer[0] = 0x00;
    memcpy(m_HIDReportBuffer + reportShift, json.c_str(), std::min(HID_MAX_BUF_SIZE, (int)json.size()));

    DBB_DEBUG("   [HID SEND] send frames\n");
    api_hid_send_frames(m_HIDHandle, HWW_CID, HWW_COMMAND, json.c_str(), json.size());
    memset(m_HIDReportBuffer, 0, HID_MAX_BUF_SIZE);
    DBB_DEBUG("   [HID SEND] read frames\n");
    api_hid_read_frames(m_HIDHandle, HWW_CID, HWW_COMMAND, m_HIDReportBuffer, sizeof(m_HIDReportBuffer));

    result.assign((const char*)m_HIDReportBuffer);
    return true;
}

/* firmware */
bool DBBCommunicationInterfaceHID::upgradeFirmware(const std::vector<unsigned char>& firmwarePadded, size_t firmwareSize, const std::string& sigCmpStr, progressCallback progressCB)
{
    std::string possibleDevicePath;
    if (findDevice(possibleDevicePath) != DBBDeviceState::Bootloader || !openConnectionAtPath(possibleDevicePath)) {
        return false;
    }

    std::vector<unsigned char> data;
    std::string result;
    uint16_t cmd;
    uint8_t* ptr = (uint8_t*)&cmd;
    *ptr = 'v';
    ptr++;
    *ptr = '0';

    sendBootloaderCmd(cmd, data, result);
    if (result.size() != 1 || result[0] != 'v') {
        closeConnection();
        return false;
    }

    ptr = (uint8_t*)&cmd;
    *ptr = 's';
    ptr++;
    *ptr = '0';
    sendBootloaderCmd(cmd, data, result);

    ptr = (uint8_t*)&cmd;
    *ptr = 'e';
    ptr++;
    *ptr = 0xff;
    sendBootloaderCmd(cmd, data, result);
    int cnt = 0;
    size_t pos = 0;
    int nChunks = ceil(firmwareSize / (float)FIRMWARE_CHUNKSIZE);
    progressCB(0.0);

    ptr = (uint8_t*)&cmd;
    *ptr = 'w';
    ptr++;
    while (pos + FIRMWARE_CHUNKSIZE < firmwarePadded.size()) {
        std::vector<unsigned char> chunk(firmwarePadded.begin() + pos, firmwarePadded.begin() + pos + FIRMWARE_CHUNKSIZE);

        *ptr = cnt % 0xff;
        sendBootloaderCmd(cmd, chunk, result);
        progressCB(1.0 / nChunks * cnt);
        pos += FIRMWARE_CHUNKSIZE;
        if (result != "w0") {
            closeConnection();
            return false;
        }

        if (pos >= firmwareSize)
            break;
        cnt++;
    }

    ptr = (uint8_t*)&cmd;
    *ptr = 's';
    ptr++;
    *ptr = '0';
    sendBootloaderCmd(cmd, std::vector<unsigned char>(sigCmpStr.begin(), sigCmpStr.end()), result);
    DBB_DEBUG("   [FW] FW upgrade result: %s\n", result.c_str());
    if (result.size() < 2 || (result[0] != 's' && result[1] != '0')) {
        closeConnection();
        return false;
    }
    progressCB(1.0);
    closeConnection();
    return true;
}

bool DBBCommunicationInterfaceHID::sendBootloaderCmd(const uint16_t cmd, const std::vector<unsigned char>& data, std::string& resultOut)
{
    int res, cnt = 0;

    if (!m_HIDHandle)
        return false;

    assert(data.size() <= HID_MAX_BUF_SIZE - 2);
    memset(m_HIDReportBuffer, 0xFF, HID_MAX_BUF_SIZE);
    int reportShift = 0;
#ifdef DBB_ENABLE_HID_REPORT_SHIFT
    reportShift = 1;
    m_HIDReportBuffer[0] = 0x00;
#endif
    memcpy(&m_HIDReportBuffer[0 + reportShift], &cmd, 2);
    if (data.size()) {
        memcpy((void*)&m_HIDReportBuffer[2 + reportShift], (unsigned char*)&data[0], data.size());
    }

    if (hid_write(m_HIDHandle, (unsigned char*)m_HIDReportBuffer, HID_BL_BUF_SIZE_W + reportShift) == -1) {
        return false;
    }
    memset(m_HIDReportBuffer, 0, HID_MAX_BUF_SIZE);
    while (cnt < HID_BL_BUF_SIZE_R) {
        res = hid_read(m_HIDHandle, m_HIDReportBuffer + cnt, HID_BL_BUF_SIZE_R);
        if (res < 0) {
            return false;
        }
        cnt += res;
    }

    resultOut.assign((const char*)m_HIDReportBuffer);
    return true;
}
