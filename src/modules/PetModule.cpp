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

#include "mesh/generated/meshtastic/pet.pb.h"
#include "pb_decode.h"
#include "pb_encode.h"

#include <SHA256.h>

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

// Generic method to encode a protobuf
template <typename T>
bool encodeProto(const T &msg, const pb_msgdesc_t *fields, uint8_t *outBuf, size_t outBufSize, size_t &outLen)
{
    pb_ostream_t stream = pb_ostream_from_buffer(outBuf, outBufSize);
    if (!pb_encode(&stream, fields, &msg)) {
        return false;
    }
    outLen = stream.bytes_written;
    return true;
}

// Generic method to decode a protobuf
template <typename T> bool decodeProto(T &msg, const pb_msgdesc_t *fields, const uint8_t *inBuf, size_t inLen)
{
    pb_istream_t stream = pb_istream_from_buffer(inBuf, inLen);
    return pb_decode(&stream, fields, &msg);
}

// Create a PetEnvelope from an already-encoded payload.
// Signs the payload using the provided private key.
// publicKey may be null if omitted (e.g., server-signed messages).
bool createEnvelope(const uint8_t *payload, size_t payloadLen, PetMessageType type,
                    const uint8_t *signingPrivKey, // 32 bytes
                    const uint8_t *signerPubKey,   // 65 bytes
                    uint8_t *outBuf, size_t outBufSize, size_t &outLen)
{
    PetEnvelope env = PetEnvelope_init_default;
    env.version = 1;
    env.message_type = type;

    // Copy payload
    if (payloadLen > sizeof(env.payload.bytes))
        return false;
    memcpy(env.payload.bytes, payload, payloadLen);
    env.payload.size = payloadLen;

    // Sign payload
    size_t sigLen = 64;
    if (!ecdsa_sign_atomic(signingPrivKey, payload, payloadLen, env.signature.bytes, sigLen)) {
        return false;
    }
    env.signature.size = sigLen;

    memcpy(env.public_key.bytes, signerPubKey, 65);
    env.public_key.size = 65;
    // Though technically optional in general, not optional for any enveloped messages this codebase creates.

    // Encode envelope
    return encodeProto(env, PetEnvelope_fields, outBuf, outBufSize, outLen);
}

// Verify an incoming envelope and extract the payload.
// Returns true if signature is valid and payload is copied out.
bool verifyEnvelope(const PetEnvelope &env,
                    const uint8_t *serverPubKey, // 65 bytes
                    uint8_t *outPayload, size_t &outPayloadLen)
{
    // Determine which key to use
    const uint8_t *pubKey = nullptr;

    if (env.public_key.size == 65) {
        // Pet-signed message
        pubKey = env.public_key.bytes;
    } else {
        // Server-signed message
        pubKey = serverPubKey;
    }

    // Verify signature
    if (!ecdsa_verify_atomic(pubKey, env.payload.bytes, env.payload.size, env.signature.bytes, env.signature.size)) {
        return false;
    }

    // Copy payload out
    if (env.payload.size > outPayloadLen)
        return false;
    memcpy(outPayload, env.payload.bytes, env.payload.size);
    outPayloadLen = env.payload.size;

    return true;
}

// Decode the inner message after verifying envelope.
// Caller must pass the correct message type.
template <typename T> bool decodeVerifiedPayload(const uint8_t *payload, size_t payloadLen, T &msg, const pb_msgdesc_t *fields)
{
    return decodeProto(msg, fields, payload, payloadLen);
}

// Send PetAnnouncement
bool sendPetAnnouncement(const uint8_t petPriv[32], const uint8_t petPub[65], const uint8_t ownerPub[65], uint8_t *outBuf,
                         size_t outBufSize, size_t &outLen)
{
    PetAnnouncement ann = PetAnnouncement_init_default;
    ann.version = 1;

    memcpy(ann.pet_public_key.bytes, petPub, 65);
    ann.pet_public_key.size = 65;

    memcpy(ann.owner_public_key.bytes, ownerPub, 65);
    ann.owner_public_key.size = 65;

    uint8_t payload[256];
    size_t payloadLen = sizeof(payload);

    if (!encodeProto(ann, PetAnnouncement_fields, payload, sizeof(payload), payloadLen))
        return false;

    return createEnvelope(payload, payloadLen, PetMessageType_PET_MESSAGE_TYPE_ANNOUNCEMENT, petPriv, petPub, outBuf, outBufSize,
                          outLen);
}

// Send PetAction
bool sendPetAction(const uint8_t petPriv[32], const uint8_t petPub[65], const PetStatus &status, const PetTimeSignal &ts,
                   const uint8_t *actionBytes, size_t actionLen, uint64_t nonce,
                   const PetAnnouncement *otherPet, // optional
                   uint8_t *outBuf, size_t outBufSize, size_t &outLen)
{
    PetAction act = PetAction_init_default;
    act.version = 1;

    act.time_signal = ts;
    act.pet_status = status;

    if (actionLen > sizeof(act.action.bytes))
        return false;
    memcpy(act.action.bytes, actionBytes, actionLen);
    act.action.size = actionLen;

    act.nonce = nonce;

    if (otherPet) {
        act.other_pet = *otherPet;
    }

    uint8_t payload[256];
    size_t payloadLen = sizeof(payload);

    if (!encodeProto(act, PetAction_fields, payload, sizeof(payload), payloadLen))
        return false;

    return createEnvelope(payload, payloadLen, PetMessageType_PET_MESSAGE_TYPE_ACTION, petPriv, petPub, outBuf, outBufSize,
                          outLen);
}

// Handle an incoming envelope and decode the inner message.
// Returns the message type, or PetMessageType_PET_MESSAGE_TYPE_UNKNOWN on failure.
PetMessageType handleIncomingEnvelope(const uint8_t *buf, size_t len, const uint8_t serverPubKey[65])
{
    PetEnvelope env = PetEnvelope_init_default;

    if (!decodeProto(env, PetEnvelope_fields, buf, len))
        return PetMessageType_PET_MESSAGE_TYPE_UNKNOWN;

    uint8_t payload[256];
    size_t payloadLen = sizeof(payload);

    if (!verifyEnvelope(env, serverPubKey, payload, payloadLen))
        return PetMessageType_PET_MESSAGE_TYPE_UNKNOWN;

    return env.message_type;
}

const std::array<uint8_t, 30> petNUMSalt = {0x74, 0x68, 0x69, 0x73, 0x69, 0x73, 0x61, 0x6e, 0x6f, 0x74,
                                            0x68, 0x69, 0x6e, 0x67, 0x75, 0x70, 0x6d, 0x79, 0x73, 0x6c,
                                            0x65, 0x65, 0x76, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72};

int hashDerivedInt(int exclBound, uint8_t *data, int dataLen)
{
    SHA256 hash;
    uint8_t outputBuf[32];
    size_t posn;
    uint8_t size = dataLen;
    uint8_t inc = 16;
    hash.reset();
    for (posn = 0; posn < size; posn += inc) {
        size_t len = size - posn;
        if (len > inc)
            len = inc;
        hash.update(data + posn, len);
    }
    hash.finalize(outputBuf, 32);
    uint32_t result = 0;
    for (size_t i = 0; i < 32; i++) {
        result = ((uint64_t)result * 256 + outputBuf[i]) % exclBound;
    }
    return result;
}

int getSpecies(const uint8_t petPub[65])
{
    uint8_t saltBuffer[65 + 30];
    memcpy(saltBuffer, petPub, 65);
    memcpy(saltBuffer + 65, petNUMSalt.data(), 30);
    return hashDerivedInt(5, saltBuffer, 65 + 30);
}

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

void PetModule::handleInit() {}
void PetModule::handleHatcheryLoad() {}
void PetModule::handleHatcheryMenu() {}
void PetModule::handleEggMenu() {}
void PetModule::handlePetMenu() {}
void PetModule::setScreen(PetScreen newScreen) {}
void PetModule::nextSelection() {}
void PetModule::prevSelection() {}
bool PetModule::hasValidPet()
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
    /* if (state->frameState == IN_TRANSITION) {
        display->clear();
        display->setPixel(2, 2);
    } else {
        display->clearPixel(2, 2);
    } */
    switch (currentScreen) {

    case PetScreen::Init:
        display->setTextAlignment(TEXT_ALIGN_CENTER);
        display->setFont(FONT_SMALL);
        display->drawString(display->getWidth() / 2, display->getHeight() / 2, "Pet_Init");
        break;

    case PetScreen::HatcheryLoad:
        display->setTextAlignment(TEXT_ALIGN_CENTER);
        display->setFont(FONT_SMALL);
        display->drawString(display->getWidth() / 2, display->getHeight() / 2, "Pet_HatcheryLoad");
        break;

    case PetScreen::HatcheryMenu:
        display->setTextAlignment(TEXT_ALIGN_CENTER);
        display->setFont(FONT_SMALL);
        display->drawString(display->getWidth() / 2, display->getHeight() / 2, "Pet_HatcheryMenu");
        break;

    case PetScreen::EggMenu:
        display->setTextAlignment(TEXT_ALIGN_CENTER);
        display->setFont(FONT_SMALL);
        display->drawString(display->getWidth() / 2, display->getHeight() / 2, "Pet_EggMenu");
        break;

    case PetScreen::PetMenu:
        display->setTextAlignment(TEXT_ALIGN_CENTER);
        display->setFont(FONT_SMALL);
        display->drawString(display->getWidth() / 2, display->getHeight() / 2, "Pet_PetMenu");
        break;
    }

    /* display->drawXbm(x + (SCREEN_WIDTH - icon_width) / 2, y + (SCREEN_HEIGHT - FONT_HEIGHT_MEDIUM - icon_height) / 2 + 2 + 10,
                     icon_width, icon_height, icon_bits); */
}
