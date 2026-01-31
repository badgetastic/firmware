#include "configuration.h"
#if ARCH_PORTDUINO
#include "PortduinoGlue.h"
#endif
#include "PetModule.h"
#include "graphics/ScreenFonts.h"
#include "graphics/images.h"
#include <OLEDDisplay.h>
#include <Throttle.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include <Preferences.h>

#include "pb_decode.h"
#include "pb_encode.h"
#include "pet.pb.h"

#define SCREEN_WIDTH display->getWidth()
#define SCREEN_HEIGHT display->getHeight()

namespace
{
bool ecdsa_generate_keypair_atomic(uint8_t privOut[32], uint8_t pubOut[65])
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "ecdsa_keygen_atomic";
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0) {
        return false;
    }

    // Generate keypair on secp256r1
    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &drbg) != 0) {
        return false;
    }

    // Export private key (always 32 bytes)
    if (mbedtls_mpi_write_binary(&ctx.d, privOut, 32) != 0) {
        return false;
    }

    // Export public key (always 65 bytes in uncompressed format)
    size_t pubLen = 0;
    if (mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pubOut, 65) != 0) {
        return false;
    }

    // Sanity check (should always be 65)
    if (pubLen != 65) {
        return false;
    }

    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    return true;
}

bool ecdsa_sign_atomic(const uint8_t privKey[32], const uint8_t *msg, size_t msgLen, uint8_t *sigOut, size_t &sigLenOut)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "ecdsa_sign_atomic";
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0) {
        return false;
    }

    // Load curve
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        return false;

    // Load private key
    if (mbedtls_mpi_read_binary(&ctx.d, privKey, 32) != 0)
        return false;

    // Compute public key from private key
    if (mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, mbedtls_ctr_drbg_random, &drbg) != 0)
        return false;

    // Sign
    int ret =
        mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, msg, msgLen, sigOut, &sigLenOut, mbedtls_ctr_drbg_random, &drbg);

    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    return ret == 0;
}

bool ecdsa_verify_atomic(const uint8_t pubKey[65], const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t sigLen)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    // Load curve
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        return false;

    // Load public key (uncompressed)
    if (mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pubKey, 65) != 0)
        return false;

    // Verify
    int ret = mbedtls_ecdsa_read_signature(&ctx, msg, msgLen, sig, sigLen);

    mbedtls_ecdsa_free(&ctx);
    return ret == 0;
}

const std::array<uint8_t, 65> petServerPublicKey = {0x04, 0x56, 0xd8, 0x24, 0xbf, 0x03, 0x6e, 0x32, 0x19, 0xfc, 0x4f, 0xd1, 0x70,
                                                    0x33, 0x41, 0x3d, 0x7a, 0x2b, 0xb3, 0xaf, 0xdc, 0xbd, 0x0e, 0x3a, 0x48, 0x5d,
                                                    0x5b, 0xaf, 0x6d, 0xb3, 0x24, 0x64, 0x51, 0xe5, 0x46, 0x3d, 0x43, 0x72, 0xe0,
                                                    0x8b, 0x7c, 0x7c, 0x33, 0xee, 0x05, 0x09, 0x03, 0x11, 0x48, 0x91, 0x10, 0x81,
                                                    0x97, 0xb6, 0xad, 0x1a, 0xa6, 0x19, 0x98, 0x3d, 0x7b, 0x92, 0x1c, 0x3f, 0x8a};

} // namespace

PetModule *petModule;

PetModule::PetModule()
    : SinglePortModule("pet", meshtastic_PortNum_PRIVATE_APP), concurrency::OSThread("Pet"), currentScreen(PetScreen::Init),
      currentSelection(0)
{
    LOG_INFO("PetModule is enabled");
    // this->inputObserver.observe(inputBroker);
    prefs.begin("PetModule", false);
    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
}

void handleInit() {}
void handleHatcheryLoad() {}
void handleHatcheryMenu() {}
void handleEggMenu() {}
void handlePetMenu() {}
void setScreen(PetScreen newScreen) {}
void nextSelection() {}
void prevSelection() {}
bool hasValidPet()
{
    return false;
}

int32_t PetModule::runOnce()
{
    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
    return 5000;
}

bool PetModule::shouldDraw()
{
    return true;
}

void PetModule::drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{

    display->drawXbm(x + (SCREEN_WIDTH - icon_width) / 2, y + (SCREEN_HEIGHT - FONT_HEIGHT_MEDIUM - icon_height) / 2 + 2 + 10,
                     icon_width, icon_height, icon_bits);
}
