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
    int i = 10;
    DBBDeviceManager dbb([](const DBBDeviceState state, const std::string pID) {
        printf("Device state: %d\n", state);
    });
    std::string result;
    std::string passphrase = "jonas";
    dbb.sendCommand("{\"led\" : \"blink\"}", passphrase, result, [](const std::string& out, int status){ printf("%s\n", out.c_str()); });
    dbb.sendCommand("{\"device\" : \"info\"}", passphrase, result, [](const std::string& out, int status){ printf("%s\n", out.c_str()); });

    /*
    DBBDeviceManager *ptr = &dbb;
    std::thread testThread = std::thread([ptr, &passphrase, &result]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        ptr->sendCommand("{\"led\" : \"blink\"}", passphrase, result, [](const std::string& res, int status){ printf("%s\n", res.c_str()); });
        ptr->sendCommand("{\"device\" : \"info\"}", passphrase, result, [](const std::string& res, int status){ printf("%s\n", res.c_str()); });
    });


    testThread.join();
    */


    /*
    if (!dbb.sendSynchronousCommand("{\"led\" : \"blink\"}", passphrase, result)) {
        printf("Sync failed");
    }
    */
    printf("%s\n", result.c_str());

    //dbb.sendCommand("{\"bootloader\" : \"unlock\"}", passphrase, result, [&](const std::string& out, int status){ printf("%s\n", out.c_str()); });
    //dbb.upgradeFirmware("/tmp/firmware.deterministic.2.1.1.signed.bin");

    dbb.sendCommand("{\"password\" : \"jonas1\"}", passphrase, result, [](const std::string& out, int status){ printf("%s\n", out.c_str()); });
    dbb.sendCommand("{\"password\" : \"jonas\"}", "jonas1", result, [](const std::string& out, int status){ printf("%s\n", out.c_str()); });
    dbb.sendCommand("{\"led\" : \"blink\"}", passphrase, result, [](const std::string& out, int status){ printf("%s\n", out.c_str()); });
}

int main() {
    testAES();
    testDBB();
    return 1;
}
