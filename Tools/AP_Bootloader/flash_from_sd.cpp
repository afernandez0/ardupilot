#include <AP_HAL/AP_HAL.h>

#include "flash_from_sd.h"

// Access to SD
#include "ch.h"
#include "ff.h"

#include <string.h>

#if AP_BOOTLOADER_FLASH_FROM_SD_ENABLED

#include "md5.h"

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include "stm32_util.h"

#include <AP_HAL_ChibiOS/hwdef/common/flash.h>
#include <AP_Math/AP_Math.h>
#include "support.h"

// swiped from support.cpp:
static const uint8_t *flash_base = (const uint8_t *)(0x08000000 + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024U);


// taken from AP_Common.cpp as we don't want to compile the AP_Common
// directory.  This function is defined in AP_Common.h - so we can't
// use "static" here.
/**
 * return the numeric value of an ascii hex character
 * 
 * @param[in] a Hexadecimal character 
 * @return  Returns a binary value
 */
int16_t char_to_hex(char a)
{
    if (a >= 'A' && a <= 'F')
        return a - 'A' + 10;
    else if (a >= 'a' && a <= 'f')
        return a - 'a' + 10;
    else
        return a - '0';
}



#define MAX_IO_SIZE 4096
static uint8_t buffer[MAX_IO_SIZE];

// a class which provides parsing functionality for abin files;
// inheritors must supply a function to deal with the body of the abin
// and may supply methods run() (to initialise their state) and
// name_value_callback (to handle name/value pairs extracted from the
// abin header.
class ABinParser {
public:
    ABinParser(const char *_path) :
        path{_path}
    { }
    virtual ~ABinParser() {}

    virtual bool run() = 0;

protected:

    virtual void name_value_callback(const char *name, const char *value) {}
    virtual void body_callback(const uint8_t *bytes, uint32_t n) = 0;
    bool parse();

private:

    const char *path;

};

bool ABinParser::parse()
{
    FIL fh;
    if (f_open(&fh, path, FA_READ) != FR_OK) {
        return false;
    }
    enum class State {
        START_NAME=17, // "MD5: "
        ACCUMULATING_NAME=19,
        ACCUMULATING_VALUE = 30,
        START_BODY = 40,
        PROCESSING_BODY = 45,
        SKIPPING_POST_COLON_SPACES = 50,
        START_VALUE = 55,
    };

    State state = State::START_NAME;
    uint16_t name_start = 0;
    uint16_t name_end = 0;
    uint16_t value_start = 0;
    // for efficiency we assume all headers are within the first chunk
    // read i.e. the name/value pairs do not cross a MAX_IO_SIZE
    // boundary
    while (true) {
        UINT bytes_read;
        if (f_read(&fh, buffer, sizeof(buffer), &bytes_read) != FR_OK) {
            return false;
        }
        if (bytes_read > sizeof(buffer)) {
            // error
            return false;
        }
        if (bytes_read == 0) {
            break;
        }
        for (uint16_t i=0; i<bytes_read; i++) {
            switch (state) {
            case State::START_NAME: {
                // check for delimiter:
                if (bytes_read-i >= 3) {
                    if (!strncmp((char*)&buffer[i], "--\n", bytes_read-i)) {
                        // end of headers
                        i += 2;
                        state = State::START_BODY;
                        continue;
                    }
                }
                // sanity check input:
                if (buffer[i] == ':') {
                    // zero-length name?! just say no:
                    return false;
                }
                if (buffer[i] == '\n') {
                    // empty line... ignore it
                    continue;
                }
                name_start = i;
                state = State::ACCUMULATING_NAME;
                continue;
            }
            case State::ACCUMULATING_NAME: {
                if (buffer[i] == '\n') {
                    // no colon on this line; just say no:
                    return false;
                }
                if (buffer[i] == ':') {
                    name_end = i;
                    state = State::SKIPPING_POST_COLON_SPACES;
                    continue;
                }
                // continue to accumulate name
                continue;
            }
            case State::SKIPPING_POST_COLON_SPACES:
                if (buffer[i] == ' ') {
                    // continue to accumulate spaces
                    continue;
                }
                state = State::START_VALUE;
                FALLTHROUGH;
            case State::START_VALUE:
                value_start = i;
                state = State::ACCUMULATING_VALUE;
                FALLTHROUGH;
            case State::ACCUMULATING_VALUE: {
                if (buffer[i] != '\n') {
                    // continue to accumate value bytes
                    continue;
                }
                char name[80];
                char value[80];
                strncpy(name, (char*)&buffer[name_start], MIN(sizeof(name)-1, name_end-name_start));
                strncpy(value, (char*)&buffer[value_start], MIN(sizeof(value)-1, i-value_start));
                name_value_callback(name, value);
                state = State::START_NAME;
                continue;
            }
            case State::START_BODY:
                state = State::PROCESSING_BODY;
                FALLTHROUGH;
            case State::PROCESSING_BODY:
                body_callback(&buffer[i], bytes_read-i);
                i = bytes_read;
                continue;
            }
        }
    }

    // successfully parsed the abin.  Call the body callback once more
    // with zero bytes indicating EOF:
    body_callback((uint8_t*)"", 0);

    return true;
}

// a sub-class of ABinParser which takes the supplied MD5 from the
// abin header and compares it against the calculated md5sum of the
// abin body
class ABinVerifier : ABinParser {
public:

    using ABinParser::ABinParser;

    bool run() override {
        MD5Init(&md5_context);

        if (!parse()) {
            return false;
        }

        // verify the checksum is as expected
        uint8_t calculated_md5[16];
        MD5Final(calculated_md5, &md5_context);
        if (!memcmp(calculated_md5, expected_md5, sizeof(calculated_md5))) {
            // checksums match
            return true;
        }

        return false;
    }

protected:

    void name_value_callback(const char *name, const char *value) override {
        if (strncmp(name, "MD5", 3)) {
            // only interested in MD5 header
            return;
        }

        // convert from 32-byte-string to 16-byte number:
        for (uint8_t j=0; j<16; j++) {
            expected_md5[j] = (char_to_hex(value[j*2]) << 4) | char_to_hex(value[j*2+1]);
        }
    }

    void body_callback(const uint8_t *bytes, uint32_t nbytes) override {
        MD5Update(&md5_context, bytes, nbytes);
    }

private:

    uint8_t expected_md5[16];
    MD5Context md5_context;
};


// a sub-class of ABinParser which flashes the body of the supplied abin
class ABinFlasher : public ABinParser {
public:
    using ABinParser::ABinParser;

    bool run() override {
        // start by erasing all sectors
        for (uint8_t i = 0; flash_func_sector_size(i) != 0; i++) {
            if (!flash_func_erase_sector(i)) {
                return false;
            }
            led_toggle(LED_BOOTLOADER);
        }

        // parse and flash
        if (!parse()) {
            return false;
        }

        return !failed;
    }

protected:

    void body_callback(const uint8_t *bytes, uint32_t nbytes) override {
        if (failed) {
            return;
        }

        memcpy(&buffer[buffer_ofs], bytes, nbytes);
        buffer_ofs += nbytes;

        const uint32_t WRITE_CHUNK_SIZE = 32*1024; // must be less than size of state buffer
        // nbytes is zero after the last chunk in the body
        if (buffer_ofs > WRITE_CHUNK_SIZE || nbytes == 0) {
            uint32_t write_size = WRITE_CHUNK_SIZE;
            uint32_t padded_write_size = write_size;
            if (nbytes == 0) {
                // final chunk.  We have to align to 128 bytes
                write_size = buffer_ofs;
                padded_write_size = write_size;
                const uint8_t pad_size = 128 - (write_size % 128);
                // zero those extra bytes:
                memset(&buffer[buffer_ofs], '\0', pad_size);
                padded_write_size += pad_size;
            }
            const uint32_t ofs = uint32_t(flash_base) + flash_ofs;
            if (!stm32_flash_write(ofs, buffer, padded_write_size)) {
                failed = true;
                return;
            }
            flash_ofs += padded_write_size;
            buffer_ofs -= write_size;
            memcpy(buffer, &buffer[write_size], buffer_ofs);
            led_toggle(LED_BOOTLOADER);
        }
    }

private:

    uint32_t flash_ofs = 0;
    uint32_t buffer_ofs = 0;
    uint8_t buffer[64*1024];  // constrained by memory map on bootloader
    bool failed = false;
};


// main entry point to the flash-from-sd-card functionality; called
// from the bootloader main function
bool flash_from_sd()
{
    peripheral_power_enable();

    if (!sdcard_init()) {
        return false;
    }

    bool ret = false;

    // expected filepath for abin:
    const char *abin_path = "/ardupilot.abin";
    // we rename to this before verifying the abin:
    const char *verify_abin_path = "/ardupilot-verify.abin";
    // we rename to this before flashing the abin:
    const char *flash_abin_path = "/ardupilot-flash.abin";
    // we rename to this after flashing the abin:
    const char *flashed_abin_path = "/ardupilot-flashed.abin";

    ABinVerifier *verifier = nullptr;
    ABinFlasher *flasher = nullptr;

    FILINFO info;
    if (f_stat(abin_path, &info) != FR_OK) {
        goto out;
    }

    f_unlink(verify_abin_path);
    f_unlink(flash_abin_path);
    f_unlink(flashed_abin_path);

    // rename the file so we only ever attempt to flash from it once:
    if (f_rename(abin_path, verify_abin_path) != FR_OK) {
        // we would be nice to indicate an error here.
        // we could try to drop a message on the SD card?
        return false;
    }

    verifier = new ABinVerifier{verify_abin_path};
    if (!verifier->run()) {
        goto out;
    }

    // rename the file so we only ever attempt to flash from it once:
    if (f_rename(verify_abin_path, flash_abin_path) != FR_OK) {
        // we would be nice to indicate an error here.
        // we could try to drop a message on the SD card?
        return false;
    }

    flasher = new ABinFlasher{flash_abin_path};
    if (!flasher->run()) {
        goto out;
    }

    // rename the file to indicate successful flash:
    if (f_rename(flash_abin_path, flashed_abin_path) != FR_OK) {
        // we would be nice to indicate an error here.
        // we could try to drop a message on the SD card?
        return false;
    }

    ret = true;

out:

    delete verifier;
    verifier = nullptr;

    delete flasher;
    flasher = nullptr;

    sdcard_stop();
    // should we disable peripheral power again?!

    return ret;
}

#endif  // AP_BOOTLOADER_FLASH_FROM_SD_ENABLED


/**
 * Create a log file `bootlog.txt` on the SD card.
 * 
 * @param[in] message The log message to write.
 * @return true if successful, false otherwise.
 */
bool log_message_in_bootlog(const char *message) 
{
    return log_message_in_bootlog(message, strlen(message));
}

/**
 * Create a log file `bootlog.txt` on the SD card.
 * 
 * @param[in] message The log message to write.
 * @return true if successful, false otherwise.
 */
bool log_message_in_bootlog(const char *message, const uint16_t message_len) 
{
    FIL file;          // File object
    FRESULT res;       // Result from FatFS operations
    UINT bytes_written;

    uint16_t tmp_message_len = 0;
    if (message_len > strlen(message)) {
        tmp_message_len = strlen(message);
    } else {
        tmp_message_len = message_len;
    }

    // Limitation; < 64KB
    assert(tmp_message_len < 64*1024);

    // Initialize the SD card
    if (!sdcard_init()) {
        return false; // Initialization failed
    }
    
    // Path to the log file
    const char *log_file_path = "/bootlog.txt";
    
    // Open or create the file
    res = f_open(&file, log_file_path, FA_WRITE | FA_OPEN_APPEND);
    if (res != FR_OK) {
        // Try to create the file if it doesn't exist
        res = f_open(&file, log_file_path, FA_WRITE | FA_CREATE_NEW);
        if (res != FR_OK) {
            // File creation failed
            sdcard_stop(); // Stop SD card before returning
            return false;
        }
    }

    // Write time
    uint32_t t0 = AP_HAL::millis();

    char time_buffer[32] = {};
    
    //convert_hex_to_string(reinterpret_cast<uint8_t *>(&t0), sizeof(t0), time_buffer, false);
    itoa(t0, time_buffer, 10);

    res = f_write(&file, time_buffer, strlen(time_buffer), &bytes_written);
    if (res != FR_OK || bytes_written != strlen(time_buffer)) {
        // Writing failed
        f_close(&file);
        sdcard_stop(); // Stop SD card before returning
        return false;
    }

    // Write Separator
    res = f_write(&file, " ", 1, &bytes_written);
    if (res != FR_OK || bytes_written != 1) {
        // Writing failed
        f_close(&file);
        sdcard_stop(); // Stop SD card before returning
        return false;
    }

    // Write the message to the file
    res = f_write(&file, message, tmp_message_len, &bytes_written);
    if (res != FR_OK || bytes_written != tmp_message_len) {
        // Writing failed
        f_close(&file);
        sdcard_stop(); // Stop SD card before returning
        return false;
    }

    // Write the message to the file
    res = f_write(&file, "\n", strlen("\n"), &bytes_written);
    if (res != FR_OK || bytes_written != strlen("\n")) {
        // Writing failed
        f_close(&file);
        sdcard_stop(); // Stop SD card before returning
        return false;
    }
    
    // Close the file
    f_close(&file);
    
    // Stop the SD card
    sdcard_stop();
    
    return true;
}

// The output string must have enough space for storing the output string
// At least input_len * 2 + 1
void convert_hex_to_string(const uint8_t *input_hex, const uint16_t input_len, char *output_string, 
    bool add_spaces_flag) 
{   
    static const char * hexmap = "0123456789ABCDEF";
           
    char *pout = output_string;
    unsigned char *pin = const_cast<unsigned char *>(input_hex);
    size_t i = 0;

    for (; i < input_len - 1; i+= 2) {
        *pout++ = hexmap[(*pin >> 4) & 0xF];
        *pout++ = hexmap[(*pin++) & 0xF];
        if (add_spaces_flag)
            *pout++ = ' ';
    }

    // Convert last char
    *pout++ = hexmap[(*pin >> 4) & 0xF];
    *pout++ = hexmap[(*pin++) & 0xF];
    *pout = 0;

}

void log_bytes_in_bootlog(const uint8_t *input_hex, const uint16_t input_len)
{
    uint32_t string_len = (input_len * 3 + 1);

    // Limitation; 4 KB
    assert(string_len < 4096);

    char converted_string[string_len];

    convert_hex_to_string(input_hex, input_len, converted_string);

    log_message_in_bootlog(converted_string, string_len);
}