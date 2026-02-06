#include "configuration.h"
#if ARCH_PORTDUINO
#include "PortduinoGlue.h"
#endif
#include "LogoModule.h"
#include "graphics/ScreenFonts.h"
#include "graphics/images.h"
#include <OLEDDisplay.h>
#include <Throttle.h>

#define SCREEN_WIDTH display->getWidth()
#define SCREEN_HEIGHT display->getHeight()

LogoModule *logoModule;

LogoModule::LogoModule() : SinglePortModule("logo", meshtastic_PortNum_PRIVATE_APP), concurrency::OSThread("Logo")
{
    LOG_INFO("LogoModule is enabled");
    this->inputObserver.observe(inputBroker);

    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
}

int32_t LogoModule::runOnce()
{
    if (firstRun) {
        UIFrameEvent e;
        e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
        this->notifyObservers(&e);
        firstRun = false;
    }
    if ((millis() - inputIdle) > 60000)
        requestFocus();
    return 5000;
}

int LogoModule::handleInputEvent(const InputEvent *event)
{
    if (event->inputEvent != INPUT_BROKER_NONE) {
        inputIdle = millis();
    }
    return 0;
}

bool LogoModule::shouldDraw()
{
    return true;
}

void LogoModule::drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{

    display->drawXbm(x + (SCREEN_WIDTH - icon_width) / 2, y + (SCREEN_HEIGHT - FONT_HEIGHT_MEDIUM - icon_height) / 2 + 2 + 10,
                     icon_width, icon_height, icon_bits);
}
