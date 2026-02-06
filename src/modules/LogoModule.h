#pragma once
#if HAS_SCREEN
#include "ProtobufModule.h"
#include "input/InputBroker.h"

class LogoModule : public SinglePortModule, public Observable<const UIFrameEvent *>, private concurrency::OSThread
{

  public:
    LogoModule();
    // const char *getCurrentFlag();
    // const char *getPrevFlag();
    // const char *getNextFlag();
    // const char *getFlagByIndex(int index);

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

  protected:
    virtual int32_t runOnce() override;

    virtual bool wantUIFrame() override { return this->shouldDraw(); }
    virtual Observable<const UIFrameEvent *> *getUIFrameObservable() override { return this; }

    // virtual bool interceptingKeyboardInput() override;
    int handleInputEvent(const InputEvent *event);

    virtual void drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y) override;

    // virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

    // void loadProtoForModule();
    // bool saveProtoForModule();

    // void installDefaultFlagModuleConfig();

  private:
    CallbackObserver<LogoModule, const InputEvent *> inputObserver =
        CallbackObserver<LogoModule, const InputEvent *>(this, &LogoModule::handleInputEvent);

    bool firstRun = true;
    long inputIdle = 0;
};

extern LogoModule *logoModule;
#endif