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
    enum class PetScreen { Init, HatcheryLoad, HatcheryMenu, SendSpinner, NameEntry, EggMenu, PetMenu, PetStats };

    PetScreen currentScreen;
    int currentSelection;
    static const std::array<uint8_t, 65> petServerKey;
    void handleInit();
    void handleHatcheryLoad();
    void handleHatcheryMenu();
    void handleNameEntry();
    void handleEggMenu();
    void handlePetMenu();
    void handleSelectEgg();
    void handlePetUpdate();
    void sendNameAction();
    void sendPetAction();

    template <typename T> void fragSend(const T &msg, const pb_msgdesc_t *fields, PetMessageType pet_message_type);

    void setScreen(PetScreen newScreen);
    void firstSelection();
    void nextSelection();
    void prevSelection();
    bool hasValidPet();
    bool loadPet();
    bool savePet();
    bool textInput = false;
    bool delayedAction = true;
    PetRecord myPet;

    uint8_t privOutA[32];
    uint8_t pubOutA[65];
    bool readyA = false;
    uint8_t spA = 0;
    uint8_t privOutB[32];
    uint8_t pubOutB[65];
    bool readyB = false;
    uint8_t spB = 0;
    uint8_t privOutC[32];
    uint8_t pubOutC[65];
    bool readyC = false;
    uint8_t spC = 0;
    String nameBuf = "Egg-San";
    uint64_t last_nonce = 0;
    bool pet_loaded = false;
    bool new_pet = true;

    uint8_t frag_msg_buffer[512];
    uint8_t frag_envOut[2048];
    uint8_t fragBuf[200];
    uint8_t frag_sigOut[64];

    uint32_t rot = 0;
    PetTimeSignal last_timesignal = PetTimeSignal_init_default;

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
