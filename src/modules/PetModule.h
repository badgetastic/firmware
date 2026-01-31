#pragma once
#if HAS_SCREEN
#include "ProtobufModule.h"
#include <Preferences.h>

#include <Arduino.h>
#include <array>
#include <string>
#include <vector>

class PetModule : public SinglePortModule, public Observable<const UIFrameEvent *>, private concurrency::OSThread
{

  public:
    PetModule();

    void processPetUpdate();

    bool shouldDraw();
    // void eventUp();
    // void eventDown();
    // void eventSelect();

    // void handleGetFlag(const meshtastic_MeshPacket &req, meshtastic_AdminMessage *response);
    // void handleSetFlag(const char *from_msg);
    /*
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        return (p->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP);
    }*/

  private:
    Preferences prefs;
    enum class PetScreen { Init, HatcheryLoad, HatcheryMenu, EggMenu, PetMenu };
    PetScreen currentScreen;
    int currentSelection;
    static const std::array<uint8_t, 65> petServerKey;
    void handleInit();
    void handleHatcheryLoad();
    void handleHatcheryMenu();
    void handleEggMenu();
    void handlePetMenu();
    void setScreen(PetScreen newScreen);
    void firstSelection();
    void nextSelection();
    void prevSelection();
    bool hasValidPet();

  protected:
    virtual int32_t runOnce() override;

    virtual bool wantUIFrame() override { return this->shouldDraw(); }
    virtual Observable<const UIFrameEvent *> *getUIFrameObservable() override { return this; }

    // virtual bool interceptingKeyboardInput() override;

    virtual void drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y) override;

    // virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

    // void loadProtoForModule();
    // bool saveProtoForModule();

    // void installDefaultFlagModuleConfig();

    // int currentFlagIndex = -1;

    // char *messages[];
};

extern PetModule *petModule;

#endif