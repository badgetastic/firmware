#pragma once
#if HAS_SCREEN
#include "ProtobufModule.h"
#include "input/InputBroker.h"
#include "mesh/generated/meshtastic/pet.pb.h"
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

    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        return (p->decoded.portnum == meshtastic_PortNum_STA_PET);
    }

  private:
    // === Input Observers ===
    CallbackObserver<PetModule, const InputEvent *> inputObserver =
        CallbackObserver<PetModule, const InputEvent *>(this, &PetModule::handleInputEvent);
    Preferences prefs;
    enum class PetScreen { Init, HatcheryLoad, HatcheryMenu, NameEntry, EggMenu, PetMenu };
    PetScreen currentScreen;
    int currentSelection;
    static const std::array<uint8_t, 65> petServerKey;
    void handleInit();
    void handleHatcheryLoad();
    void handleHatcheryMenu();
    void handleNameEntry();
    void handleEggMenu();
    void handlePetMenu();

    void setScreen(PetScreen newScreen);
    void firstSelection();
    void nextSelection();
    void prevSelection();
    bool hasValidPet();
    bool textInput = false;
    bool delayedAction = true;
    bool active;
    PetRecord myPet;

    uint8_t privOutA[32];
    uint8_t pubOutA[65];
    bool readyA = false;
    uint8_t privOutB[32];
    uint8_t pubOutB[65];
    bool readyB = false;
    uint8_t privOutC[32];
    uint8_t pubOutC[65];
    bool readyC = false;

  protected:
    virtual int32_t runOnce() override;

    virtual bool wantUIFrame() override { return this->shouldDraw(); }
    virtual Observable<const UIFrameEvent *> *getUIFrameObservable() override { return this; }
    virtual bool interceptingKeyboardInput() override;
    virtual bool retainsFreetextFocus() { return true; }

    virtual int handleInputEvent(const InputEvent *event);

    virtual void drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y) override;

    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

    // void loadProtoForModule();
    // bool saveProtoForModule();

    // void installDefaultFlagModuleConfig();

    // int currentFlagIndex = -1;

    // char *messages[];
};

extern PetModule *petModule;

#endif

/*
Plan:

Transitions between modes are triggered either by a user menu interaction or a packet.
Init tries to restore state and jump to the correct mode, otherwise it directs you to hatchery init.
Hatchery Init generates 3 "eggs" the redirects you to Hatchery menu
Hatchery menu selects a Pet, saves it, then jumps to init.
If a egg mode pet, go to egg menu
Egg mode operates on 15 minute ticks
If a grown pet, go to pet menu
Pet menu operates on actions, + 15 minute ticks








*/