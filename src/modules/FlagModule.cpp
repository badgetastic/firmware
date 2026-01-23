#include "configuration.h"
#if ARCH_PORTDUINO
#include "PortduinoGlue.h"
#endif
#include "FlagModule.h"
#include "graphics/ScreenFonts.h"
#include <OLEDDisplay.h>
#include <Throttle.h>

#define SCREEN_WIDTH display->getWidth()
#define SCREEN_HEIGHT display->getHeight()

#define flag_width 92
#define flag_height 20
static unsigned char flag_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x0f,
    0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee, 0xfe, 0x07, 0xff, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3,
    0xa2, 0xfc, 0x03, 0xcf, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x90, 0x53, 0xb7, 0x80, 0x03, 0x33, 0x0b, 0x00, 0x00, 0x00,
    0xc0, 0x0f, 0xd8, 0x78, 0xf1, 0x80, 0x01, 0x33, 0x0b, 0x00, 0x00, 0x00, 0xe0, 0xe3, 0xd9, 0x18, 0x7f, 0xc0, 0x01, 0xcf,
    0x0c, 0x00, 0x00, 0x00, 0xf0, 0xf1, 0xd4, 0x3c, 0xf7, 0xc0, 0x01, 0xcf, 0x0f, 0x00, 0x00, 0x00, 0x70, 0xce, 0xd4, 0x77,
    0xd0, 0xc0, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xcf, 0x9c, 0xdb, 0x93, 0xe1, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0xdf, 0x1e, 0x98, 0x03, 0xe0, 0x00, 0x03, 0x06, 0x06, 0x8f, 0x03, 0xf0, 0xdc, 0x16, 0x06, 0x01, 0x60, 0x00, 0x0f,
    0x06, 0x86, 0xd9, 0x06, 0x00, 0x5e, 0x16, 0xcf, 0x8b, 0x70, 0x00, 0x3f, 0x06, 0xc6, 0x50, 0x00, 0x00, 0x0f, 0x80, 0x41,
    0xda, 0x70, 0x00, 0x0f, 0x06, 0xcf, 0xc0, 0x00, 0xe0, 0x0f, 0x80, 0x21, 0x7a, 0x30, 0x00, 0x03, 0x06, 0xc9, 0x80, 0x03,
    0xfc, 0x07, 0x80, 0x29, 0x69, 0x38, 0x00, 0x03, 0x06, 0xcf, 0x0e, 0x06, 0xfc, 0x01, 0x00, 0xef, 0x6d, 0x18, 0x00, 0x03,
    0x86, 0xd9, 0x1e, 0x04, 0x7c, 0x00, 0x00, 0xc2, 0x6c, 0x18, 0x00, 0x03, 0xbe, 0x99, 0xd9, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0x08, 0x00, 0x03, 0xbe, 0x19, 0x9f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0x66, 0x6c, 0x61, 0x67, 0x7b, 0x69, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x7d};

FlagModule *flagModule;

FlagModule::FlagModule() : SinglePortModule("flag", meshtastic_PortNum_PRIVATE_APP), concurrency::OSThread("Flag")
{
    flags.setStorage(storage_array);
    // this->loadProtoForModule();
    LOG_INFO("FlagModule is enabled");
    // this->inputObserver.observe(inputBroker);
    char second[20] = {0xfa, 0x63, 0xfd, 0x68, 0xe7, 0x6c, 0xf9, 0x7d, 0xaf, 0x6e,
                       0xf0, 0x50, 0xf7, 0x3e, 0xad, 0x3e, 0xf9, 0x7d, 0xe1, 0x00};
    char third[2] = {0x9c, 0x0f};
    for (int i = 0; i < 19; i++) {
        second[i] ^= third[i % 2];
    }
    LOG_INFO(second);

    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
}

int32_t FlagModule::runOnce()
{
    if (curr_flag >= 0)
        curr_flag = (curr_flag + 1) % flags.size();
    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
    return 5000;
}

void FlagModule::addFlag(String newFlag)
{
    String msg = "Adding Flag:" + newFlag;
    const char *cflg = msg.c_str();
    LOG_INFO(cflg);
    if (flags.size() >= FLAG_MODULE_MAX_FLAGS) {
        flags.remove(0);
    }
    if (newFlag.substring(0, 5).equals("flag{") && newFlag.substring(newFlag.length() - 1).equals("}")) {
        bool exists = false;
        for (int j = 0; j < flags.size(); j++) {
            if (flags.at(j).equals(newFlag)) {
                exists = true;
            }
        }
        if (!exists) {
            flags.push_back(newFlag);
            curr_flag = flags.size() - 1;
            active = true;
            requestFocus();
        }
    }
    curr_flag = flags.size() - 1;
}

/*void FlagModule::addSeededFlag(String newFlag, char* trigger, int len) {
    if(flags.size() < FLAG_MODULE_MAX_FLAGS) {
        //String logstr = "Attempted Flag (" + trigger.length();
        //logstr = logstr + "): ";
        for(int i=0; i<newFlag.length(); i++) {
            int toffset = i%len;
            char newChar = newFlag[i] ^ trigger[toffset];
            newFlag[i] = newChar;
            //char hexchar[8];
            //sprintf(hexchar, "%02X(%02X) ", newChar, trigger[toffset]);
            //logstr += hexchar;
        }

        //LOG_INFO(logstr.c_str());

        if(newFlag.substring(0,5).equals("flag{") && newFlag.substring(newFlag.length()-1).equals("}")) {
            bool exists = false;
            for(int j=0; j<flags.size(); j++) {
                if(flags.at(j).equals(newFlag)) {
                    exists = true;
                }
            }
            if(!exists) {
                flags.push_back(newFlag);
                curr_flag = flags.size() - 1;
                requestFocus();
            }
        }
    }
}*/

void FlagModule::nextFlag()
{
    if (flags.size() < 1) {
        curr_flag = -1;
    } else {
        curr_flag = (curr_flag + 1) % flags.size();
    }
}

bool FlagModule::shouldDraw()
{
    return active;
}

void FlagModule::toggle()
{
    active = !active;
    if (active) {
        LOG_DEBUG("Toggle On");
    } else {
        LOG_DEBUG("Toggle Off");
    }

    char first[16] = {0xc0, 0xca, 0xc7, 0xc1, 0xdd, 0xc4, 0x92, 0xc2, 0xc1, 0x95, 0xca, 0xdf, 0xc0, 0x95, 0xdb, 0x00};
    for (int i = 0; i < 15; i++) {
        first[i] ^= 0xa6;
    }
    addFlag(String(first));
    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
    if (active)
        requestFocus();
}

/*
ProcessMessage FlagModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    auto &p = mp.decoded;
    LOG_INFO("Received text msg from=0x%0x, id=0x%x, msg=%.*s", mp.from, mp.id, p.payload.size, p.payload.bytes);
    String message = "";
    for(int i=0; i<p.payload.size; i++) {
        message += p.payload.bytes[i];
    }
    addFlag(message);

    return ProcessMessage::CONTINUE;
}*/

void FlagModule::drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{

    display->drawXbm(x + (SCREEN_WIDTH - flag_width) / 2, y + 4, flag_width, flag_height, flag_bits);
    display->setTextAlignment(TEXT_ALIGN_CENTER);
    display->setFont(FONT_SMALL);
    if (flags.size() < 1 || curr_flag < 0) {
        display->drawString(display->getWidth() / 2 + x, 0 + y + 4 + flag_height, "No Flags Yet :-(");
    } else {
        display->drawString(display->getWidth() / 2 + x, 0 + y + 4 + flag_height, flags.at(curr_flag));
    }
}
