#include "hidapi/hidapi.h"
#include "univalue.h"
#include "crypto/aes.h"

#include "dbb.h"

#include <assert.h>
#include <string.h>

void testAES() {
    uint8_t key[32] = {0};
    uint8_t test_in[32]= {0};
    uint8_t test_out[32]= {0};
    AES256Encrypt enc(&key[0]);
    enc.Encrypt(&test_out[0], &test_in[0]);
    AES256Decrypt dec(&key[0]);
    dec.Decrypt(&test_out[0], &test_out[0]);

    assert(memcmp(&test_out[0], &test_in[0], 32) == 0);
}

void testDBB() {
    DBB dbb([](const DBBDeviceState state, const std::string pID) {
        printf("Device state: %d\n", state);
    });
    std::string commandJson0 = "{\"led\" : \"blink\"}";
    std::string commandJson1 = "{\"device\" : \"info\"}";
    std::string result;
    std::string passphrase = "jonas";
    dbb.sendCommand(commandJson0, passphrase, result, [&](const std::string&, int status){ printf("TEST\n"); });
    dbb.sendCommand(commandJson1, passphrase, result, [&](const std::string&, int status){ printf("TEST\n"); });

//    std::thread testThread = std::thread([&]() {
//        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

//        dbb.sendCommand(commandJson1, passphrase, result, [&](const std::string& res, int status){ printf("TEST %s\n", res.c_str()); });
//        dbb.sendCommand(commandJson1, passphrase, result, [&](const std::string& res, int status){ printf("TEST %s\n", res.c_str()); });
//    });

//    testThread.join();

    std::string commandJson2 =  "{\"bootloader\" : \"unlock\"}";
    dbb.sendCommand(commandJson2, passphrase, result, [&](const std::string&, int status){ printf("TEST\n"); });
    dbb.upgradeFirmware("/tmp/firmware.deterministic.2.1.1.signed.bin");
}

int main() {
    testAES();
    testDBB();
    return 1;
}
