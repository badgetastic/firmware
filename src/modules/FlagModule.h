#pragma once
#if HAS_SCREEN
#include "ProtobufModule.h"
#include "input/InputBroker.h"
#include <Vector.h>

#define FLAG_MODULE_MAX_FLAGS 10

class FlagModule : public SinglePortModule, public Observable<const UIFrameEvent *>, private concurrency::OSThread
{

  public:
    FlagModule();
    // const char *getCurrentFlag();
    // const char *getPrevFlag();
    // const char *getNextFlag();
    // const char *getFlagByIndex(int index);

    bool shouldDraw();
    // void eventUp();
    // void eventDown();
    // void eventSelect();

    void addFlag(String newFlag);
    // void addSeededFlag(String newFlag, char* trigger, int len);
    void nextFlag();
    void prevFlag();
    void toggle();

    // void handleGetFlag(const meshtastic_MeshPacket &req, meshtastic_AdminMessage *response);
    // void handleSetFlag(const char *from_msg);
    /*
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        return (p->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP);
    }*/

  protected:
    virtual int32_t runOnce() override;
    int handleInputEvent(const InputEvent *event);
    int handleUIFrameEvent(const UIFrameEvent *event);

    virtual bool wantUIFrame() override { return this->shouldDraw(); }
    virtual Observable<const UIFrameEvent *> *getUIFrameObservable() override { return this; }
    virtual bool interceptingKeyboardInput();
    virtual bool retainsFreetextFocus() { return true; }

    virtual void drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y) override;

    // virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

    // void loadProtoForModule();
    // bool saveProtoForModule();

    // void installDefaultFlagModuleConfig();

    // int currentFlagIndex = -1;

    // char *messages[];
    String storage_array[FLAG_MODULE_MAX_FLAGS];
    Vector<String> flags;
    int curr_flag = -1;
    bool enabled = false;

  private:
    // === Input Observers ===
    CallbackObserver<FlagModule, const InputEvent *> inputObserver =
        CallbackObserver<FlagModule, const InputEvent *>(this, &FlagModule::handleInputEvent);
    // CallbackObserver<FlagModule, const UIFrameEvent *> uiFrameEventObserver =
    //     CallbackObserver<FlagModule, const UIFrameEvent *>(this, &FlagModule::handleUIFrameEvent);
};

extern FlagModule *flagModule;
#endif