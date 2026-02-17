#include "configuration.h"
#if ARCH_PORTDUINO
#include "PortduinoGlue.h"
#endif
#include "PetModule.h"
#include "graphics/Screen.h"
#include "graphics/ScreenFonts.h"
#include "graphics/images.h"
#include <OLEDDisplay.h>
#include <Throttle.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include <Preferences.h>

#include "MeshService.h"

#include "input/InputBroker.h"

#include "mesh/generated/meshtastic/pet.pb.h"
#include "pb_decode.h"
#include "pb_encode.h"

#include <SHA256.h>
#include <map>

#define SCREEN_WIDTH display->getWidth()
#define SCREEN_HEIGHT display->getHeight()

#define cursor_width 8
#define cursor_height 7
static unsigned char cursor_bits[] = {0x03, 0x0f, 0x3f, 0xff, 0x31, 0x0d, 0x03};

#define egg1_width 32
#define egg1_height 48
static unsigned char egg1_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x60, 0x06, 0x00,
    0x00, 0x30, 0x0c, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x0c, 0x30, 0x00,
    0x00, 0x0c, 0x30, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06, 0x7e, 0x00, 0x00, 0x86, 0x6b, 0x00, 0x00, 0xc2, 0xd5, 0x00,
    0x00, 0xc3, 0xea, 0x00, 0x00, 0x61, 0xd5, 0x00, 0x80, 0xa1, 0xaa, 0x01, 0x80, 0x61, 0xd5, 0x01, 0x80, 0xc1, 0xaa, 0x01,
    0xc0, 0x80, 0xd5, 0x03, 0xc0, 0x00, 0x6b, 0x03, 0xc0, 0x00, 0x3c, 0x03, 0x40, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06,
    0x60, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x04, 0x20, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x04, 0xa0, 0x00, 0x00, 0x04,
    0x60, 0x01, 0x00, 0x04, 0xa0, 0x02, 0x00, 0x04, 0x60, 0x03, 0x00, 0x04, 0xa0, 0x02, 0xc0, 0x07, 0x60, 0x03, 0x70, 0x05,
    0xe0, 0x02, 0xa8, 0x06, 0x60, 0x03, 0x54, 0x07, 0xe0, 0x02, 0xac, 0x06, 0xc0, 0x03, 0x56, 0x03, 0xc0, 0x01, 0xab, 0x03,
    0x80, 0x01, 0xd5, 0x01, 0x00, 0x03, 0xeb, 0x00, 0x00, 0x06, 0x75, 0x00, 0x00, 0x1c, 0x7b, 0x00, 0x00, 0xf0, 0x1f, 0x00,
    0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define egg2_width 36
#define egg2_height 48
static unsigned char egg2_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 0x00, 0x00, 0x00, 0xf0, 0xf0, 0x01, 0x00,
    0x00, 0x38, 0x80, 0x03, 0x00, 0x00, 0x0e, 0x00, 0x07, 0x00, 0x00, 0x07, 0x00, 0x0e, 0x00, 0x00, 0x03, 0x00, 0x1c, 0x00,
    0x80, 0x01, 0x00, 0x18, 0x00, 0xc0, 0x00, 0x00, 0x30, 0x00, 0xc0, 0x00, 0x00, 0x60, 0x00, 0x60, 0x18, 0xc0, 0x60, 0x00,
    0x60, 0x30, 0x80, 0xc1, 0x00, 0x30, 0x08, 0x40, 0xc2, 0x00, 0x30, 0x00, 0x80, 0x83, 0x00, 0x30, 0x00, 0x00, 0x83, 0x01,
    0x18, 0x00, 0x00, 0x80, 0x01, 0x18, 0x01, 0x00, 0x00, 0x01, 0x18, 0x82, 0x01, 0x00, 0x01, 0x08, 0x41, 0x07, 0x00, 0x03,
    0x08, 0xc6, 0x03, 0x00, 0x03, 0x08, 0x41, 0x01, 0x00, 0x03, 0x08, 0x80, 0x00, 0x07, 0x03, 0x0c, 0x00, 0xc0, 0x0a, 0x02,
    0x0c, 0x00, 0xc0, 0x06, 0x02, 0x0c, 0x00, 0xc0, 0x03, 0x02, 0x08, 0x00, 0x0a, 0x00, 0x03, 0x08, 0x01, 0x06, 0x00, 0x03,
    0x08, 0x05, 0x00, 0x00, 0x03, 0x08, 0x04, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x18, 0x00, 0x00, 0x00, 0x01,
    0x18, 0x00, 0x00, 0x86, 0x01, 0x30, 0x00, 0x01, 0x8c, 0x01, 0x30, 0x80, 0x02, 0xca, 0x00, 0x20, 0xc0, 0x15, 0xc0, 0x00,
    0x60, 0x80, 0x0a, 0xc0, 0x00, 0x60, 0x00, 0x16, 0x60, 0x00, 0xc0, 0x00, 0x00, 0x30, 0x00, 0x80, 0x01, 0x00, 0x30, 0x00,
    0x80, 0x03, 0x00, 0x18, 0x00, 0x00, 0x07, 0x00, 0x0c, 0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x00, 0x1c, 0x80, 0x03, 0x00,
    0x00, 0x78, 0xe0, 0x01, 0x00, 0x00, 0xe0, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define egg3_width 40
#define egg3_height 48
static unsigned char egg3_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xc0, 0xef, 0x03, 0x00,
    0x00, 0xf0, 0x00, 0x0f, 0x00, 0x00, 0x78, 0x00, 0x1e, 0x00, 0x00, 0x38, 0x00, 0x3c, 0x00, 0x00, 0x0c, 0x00, 0x30, 0x00,
    0x00, 0x0e, 0x00, 0x60, 0x00, 0x00, 0x07, 0x00, 0xe0, 0x00, 0x00, 0x07, 0x00, 0xc0, 0x01, 0x80, 0x07, 0x00, 0x80, 0x01,
    0xc0, 0x05, 0x00, 0x80, 0x03, 0xc0, 0x0e, 0x00, 0x00, 0x03, 0xe0, 0x0d, 0x00, 0x00, 0x07, 0xe0, 0x0e, 0x00, 0x00, 0x06,
    0x60, 0x0d, 0x00, 0x00, 0x0c, 0xb0, 0x0a, 0x00, 0x00, 0x0c, 0x70, 0x0d, 0x00, 0x00, 0x0c, 0xb0, 0x0a, 0x00, 0x00, 0x18,
    0x58, 0x1d, 0x00, 0x00, 0x18, 0xb8, 0x1a, 0x00, 0x00, 0x18, 0x58, 0x35, 0x00, 0x00, 0x10, 0xa8, 0x3a, 0x00, 0x00, 0x30,
    0x5c, 0x35, 0x00, 0x00, 0x30, 0xac, 0x6a, 0x00, 0x00, 0x30, 0x5c, 0xd5, 0x00, 0x00, 0x30, 0xac, 0xaa, 0x01, 0x00, 0x30,
    0x5c, 0x55, 0x03, 0x00, 0x30, 0xac, 0xaa, 0x0e, 0x00, 0x30, 0x5c, 0x55, 0x7d, 0x00, 0x30, 0xac, 0xaa, 0xea, 0xff, 0x3f,
    0x5c, 0x55, 0x55, 0xfd, 0x37, 0xac, 0xaa, 0xaa, 0xaa, 0x3a, 0x58, 0x55, 0x55, 0x55, 0x35, 0xb8, 0xaa, 0xaa, 0xaa, 0x1a,
    0x58, 0x55, 0x55, 0x55, 0x1d, 0xb0, 0xaa, 0xaa, 0xaa, 0x1e, 0x70, 0x55, 0x55, 0x55, 0x0d, 0xe0, 0xaa, 0xaa, 0xaa, 0x07,
    0xc0, 0x55, 0x55, 0xd5, 0x07, 0x80, 0xab, 0xaa, 0xea, 0x03, 0x00, 0x57, 0x55, 0xf5, 0x01, 0x00, 0xbe, 0xaa, 0x7a, 0x00,
    0x00, 0xf8, 0xd7, 0x1f, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define egg4_width 40
#define egg4_height 48
static unsigned char egg4_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xc0, 0xef, 0x03, 0x00,
    0x00, 0xf0, 0x00, 0x0f, 0x00, 0x00, 0x78, 0x00, 0x1e, 0x00, 0x00, 0x38, 0x00, 0x3c, 0x00, 0x00, 0x0c, 0x00, 0x30, 0x00,
    0x00, 0x0e, 0x00, 0x60, 0x00, 0x00, 0x07, 0xe0, 0xe1, 0x00, 0x00, 0x03, 0x70, 0xc7, 0x01, 0x80, 0x01, 0xa0, 0x8e, 0x01,
    0xc0, 0x01, 0x70, 0x9d, 0x03, 0xc0, 0x00, 0xb0, 0x6a, 0x03, 0xe0, 0x00, 0x70, 0xd5, 0x07, 0x60, 0x00, 0xb0, 0xaa, 0x06,
    0x60, 0x00, 0x60, 0x55, 0x0d, 0x30, 0x00, 0xe0, 0xaa, 0x0f, 0x30, 0x00, 0x40, 0x55, 0x0f, 0x30, 0x00, 0xc0, 0xaa, 0x1e,
    0x18, 0x00, 0x80, 0x55, 0x1d, 0x18, 0x00, 0x00, 0xaf, 0x1c, 0x18, 0x00, 0x00, 0x5c, 0x17, 0x08, 0x00, 0x00, 0xe0, 0x33,
    0x0c, 0x00, 0x00, 0x80, 0x33, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30,
    0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30,
    0x0c, 0x00, 0x00, 0x00, 0x30, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x18, 0x00, 0x00, 0x00, 0x30, 0x18, 0x00, 0x00, 0x00, 0x18,
    0x18, 0x00, 0x00, 0x00, 0x18, 0x30, 0x00, 0x00, 0x00, 0x1c, 0x70, 0x00, 0x00, 0x00, 0x0c, 0xe0, 0x00, 0x00, 0x00, 0x07,
    0xc0, 0x01, 0x00, 0x80, 0x07, 0x80, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x07, 0x00, 0xe0, 0x01, 0x00, 0x3e, 0x00, 0x78, 0x00,
    0x00, 0xf8, 0xc3, 0x1f, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define egg5_width 32
#define egg5_height 48
static unsigned char egg5_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x00, 0x60, 0x06, 0x00,
    0x00, 0x30, 0x0c, 0x00, 0x00, 0x30, 0x1c, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x0c, 0x30, 0x00,
    0x00, 0x0c, 0x30, 0x00, 0x00, 0x1e, 0x60, 0x00, 0x00, 0x36, 0x60, 0x00, 0x00, 0xee, 0x60, 0x00, 0x00, 0xd7, 0xc3, 0x00,
    0x00, 0xab, 0xce, 0x00, 0x00, 0x57, 0xfd, 0x00, 0x80, 0xad, 0xaa, 0x01, 0x80, 0x79, 0xd5, 0x01, 0x80, 0xe1, 0xaa, 0x01,
    0xc0, 0xc0, 0x57, 0x03, 0xc0, 0x00, 0xfe, 0x03, 0xc0, 0x00, 0x80, 0x03, 0x60, 0x00, 0x00, 0x06, 0xe0, 0x00, 0x00, 0x06,
    0xe0, 0x01, 0x00, 0x06, 0x60, 0x07, 0x00, 0x06, 0xa0, 0x1c, 0x00, 0x04, 0x60, 0xf5, 0x00, 0x04, 0xa0, 0xaa, 0x9f, 0x07,
    0xe0, 0x55, 0xfd, 0x07, 0xa0, 0xaf, 0xaa, 0x06, 0x20, 0x7e, 0x55, 0x05, 0x20, 0xe0, 0xab, 0x06, 0x20, 0x00, 0xff, 0x07,
    0x60, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06, 0x60, 0x00, 0x00, 0x06, 0xc0, 0x00, 0x00, 0x03, 0xc0, 0x03, 0x80, 0x03,
    0x80, 0x0f, 0x80, 0x01, 0x00, 0x3b, 0xc0, 0x00, 0x00, 0xfe, 0xef, 0x00, 0x00, 0xbe, 0x7f, 0x00, 0x00, 0xf8, 0x1f, 0x00,
    0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define title_width 128
#define title_height 23
static unsigned char title_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0e, 0x00, 0xe0, 0x01, 0x18, 0xf8, 0xff, 0x3f, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0xe0, 0x01,
    0x3c, 0xfc, 0xff, 0x7f, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0xc0, 0x01, 0x3c, 0xbc, 0xff, 0x7f, 0x3e,
    0x00, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xc0, 0x7f, 0x70, 0xc0, 0x01, 0x18, 0x1c, 0x9f, 0x73, 0x7e, 0xfc, 0x00, 0xf0, 0x07, 0x3e,
    0x00, 0xe0, 0x7f, 0xfc, 0xc1, 0x01, 0x00, 0x1c, 0x86, 0x23, 0x7e, 0xfc, 0x3d, 0xf8, 0x07, 0xff, 0xc1, 0xc3, 0x3f, 0xfe, 0xc3,
    0x1f, 0x1c, 0x38, 0x80, 0x03, 0x77, 0xfc, 0x7f, 0x38, 0x0f, 0xff, 0xe1, 0x0f, 0x07, 0xff, 0xc3, 0x3f, 0x1c, 0xf8, 0x80, 0x03,
    0x77, 0xf8, 0xff, 0x98, 0x0f, 0xe3, 0xf0, 0x1f, 0x07, 0x87, 0xc3, 0x7f, 0x18, 0xf0, 0x83, 0x83, 0xe3, 0x38, 0xff, 0xf0, 0x0f,
    0xf3, 0x78, 0x1e, 0x07, 0x07, 0xc0, 0x7f, 0x18, 0xc0, 0x87, 0x83, 0xe3, 0x38, 0xc7, 0xf1, 0x1f, 0x7f, 0x38, 0x1c, 0x07, 0x03,
    0xc0, 0x71, 0x18, 0x0e, 0x87, 0x83, 0xff, 0x38, 0xc7, 0x79, 0x1e, 0x3f, 0x38, 0x1c, 0x87, 0x03, 0xc6, 0x71, 0x18, 0x1e, 0x86,
    0xc3, 0xff, 0x38, 0xc7, 0x39, 0x1e, 0x7f, 0x38, 0x1c, 0x07, 0x07, 0xc7, 0x71, 0x1c, 0x3e, 0x86, 0xc3, 0xc7, 0x39, 0xc7, 0x39,
    0x9e, 0xff, 0x39, 0x1c, 0x0f, 0x87, 0xe7, 0x71, 0x3c, 0xfe, 0xe7, 0xcf, 0xc3, 0x39, 0xc7, 0xf9, 0x9f, 0xff, 0xfb, 0x0f, 0x3f,
    0xfe, 0xf3, 0x71, 0x7e, 0xf0, 0xe3, 0xef, 0xc3, 0x39, 0xc7, 0xf1, 0x9f, 0x81, 0xf3, 0x0f, 0x3f, 0xfe, 0xf1, 0x71, 0x7e, 0x00,
    0xe0, 0xcf, 0xc1, 0x39, 0xc0, 0xe1, 0xd9, 0x01, 0xe7, 0x07, 0x3c, 0xf8, 0x80, 0x71, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xc0, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x87, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define spinner_width 48
#define spinner_height 48
static unsigned char spinner_bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00,
    0x00, 0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x00, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0xff,
    0x03, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x3f, 0x80, 0x00, 0x00, 0x00, 0xc0, 0x1f, 0x00, 0x01, 0x00,
    0x00, 0xc0, 0x0f, 0x00, 0x03, 0x00, 0x00, 0xe0, 0x0f, 0x00, 0x03, 0x00, 0x00, 0xe0, 0x07, 0x00, 0x03, 0x00, 0x00, 0xe0, 0x07,
    0x00, 0x03, 0x00, 0x00, 0xe0, 0x07, 0x80, 0x07, 0x00, 0x00, 0xe0, 0x07, 0x80, 0x03, 0x00, 0x00, 0xc0, 0x0f, 0xc0, 0x03, 0x00,
    0x00, 0xc0, 0x0f, 0xe0, 0x03, 0x00, 0x00, 0x80, 0x7f, 0xf8, 0x01, 0x00, 0x00, 0x80, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x7f, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

namespace
{
static const char *eggMenuItems[] = {"Sing", "Hug", "Rock", "Back"};
static const int eggMenuCount = 4;

static const char *petMenuItems[] = {"Feed", "Play", "Clean", "Sing", "Battle", "Stats", "Back"};
static const int petMenuCount = 7;

void drawXbmPet(OLEDDisplay *display, int16_t center_x, int16_t center_y, uint8_t petSP)
{
    switch (petSP) {
    case 0:
        display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        break;
    case 1:
        display->drawXbm(center_x - (egg2_width / 2), center_y - (egg2_height / 2), egg2_width, egg2_height, egg2_bits);
        break;
    case 2:
        display->drawXbm(center_x - (egg3_width / 2), center_y - (egg3_height / 2), egg3_width, egg3_height, egg3_bits);
        break;
    case 3:
        display->drawXbm(center_x - (egg4_width / 2), center_y - (egg4_height / 2), egg4_width, egg4_height, egg4_bits);
        break;
    case 4:
        display->drawXbm(center_x - (egg5_width / 2), center_y - (egg5_height / 2), egg5_width, egg5_height, egg5_bits);
        break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
        // case 0:
        //     display->drawXbm(center_x - (egg1_width / 2), center_y - (egg1_height / 2), egg1_width, egg1_height, egg1_bits);
        //     break;
    }
}

// ====== CONFIGURABLE LIMITS ======
static const uint8_t MAX_INFLIGHT = 8;
static const uint8_t MAX_FRAGMENTS = 16;
static const uint8_t MAX_SEEN = 16;

// ====== SEEN MESSAGE CACHE ======
struct SeenEntry {
    uint32_t msg_id = 0;
    uint32_t timestamp = 0;
    bool used = false;
};

static SeenEntry seenList[MAX_SEEN];

// ====== INFLIGHT FRAGMENT REASSEMBLY ======
struct InflightMsg {
    uint32_t msg_id = 0;
    uint32_t timestamp = 0;
    uint8_t fragment_count = 0;
    bool used = false;

    struct FragPart {
        bool present = false;
        uint16_t size = 0;
        char data[200]; // adjust as needed
    };

    FragPart parts[MAX_FRAGMENTS];
};

static InflightMsg inflightList[MAX_INFLIGHT];

static const uint32_t FRAG_TTL_SEC = 15;

static void pruneFragments()
{
    uint32_t now = millis() / 1000;

    // Prune inflight
    for (auto &e : inflightList) {
        if (e.used && (now - e.timestamp > FRAG_TTL_SEC)) {
            e.used = false;
        }
    }

    // Prune seen
    for (auto &s : seenList) {
        if (s.used && (now - s.timestamp > FRAG_TTL_SEC)) {
            s.used = false;
        }
    }
}

static InflightMsg *getInflight(uint32_t msg_id)
{
    // First try to find existing entry
    for (auto &e : inflightList) {
        if (e.used && e.msg_id == msg_id)
            return &e;
    }

    // Otherwise allocate a new slot
    for (auto &e : inflightList) {
        if (!e.used) {
            e.used = true;
            e.msg_id = msg_id;
            e.timestamp = millis() / 1000;
            memset(e.parts, 0, sizeof(e.parts));
            return &e;
        }
    }

    return nullptr; // no space
}

static void markSeen(uint32_t msg_id)
{
    uint32_t now = millis() / 1000;

    // Try to update existing
    for (auto &s : seenList) {
        if (s.used && s.msg_id == msg_id) {
            s.timestamp = now;
            return;
        }
    }

    // Insert new
    for (auto &s : seenList) {
        if (!s.used) {
            s.used = true;
            s.msg_id = msg_id;
            s.timestamp = now;
            return;
        }
    }

    // If full, overwrite oldest
    uint8_t oldest = 0;
    for (uint8_t i = 1; i < MAX_SEEN; i++) {
        if (seenList[i].timestamp < seenList[oldest].timestamp)
            oldest = i;
    }
    seenList[oldest].msg_id = msg_id;
    seenList[oldest].timestamp = now;
}

static bool isSeen(uint32_t msg_id)
{
    for (auto &s : seenList) {
        if (s.used && s.msg_id == msg_id)
            return true;
    }
    return false;
}

static bool processFragment(const PetFragment &frag, std::string &outFull)
{
    pruneFragments();

    uint32_t msg_id = frag.msg_id;

    if (isSeen(msg_id))
        return false;

    InflightMsg *entry = getInflight(msg_id);
    if (!entry)
        return false; // no space

    entry->timestamp = millis() / 1000;
    entry->fragment_count = frag.fragment_count;

    if (frag.fragment_index >= MAX_FRAGMENTS)
        return false;

    auto &slot = entry->parts[frag.fragment_index];
    slot.present = true;
    slot.size = frag.data.size;
    memcpy(slot.data, frag.data.bytes, frag.data.size);

    // Check if all fragments arrived
    for (uint8_t i = 0; i < entry->fragment_count; i++) {
        if (!entry->parts[i].present)
            return false;
    }

    // Reassemble
    outFull.clear();
    for (uint8_t i = 0; i < entry->fragment_count; i++) {
        outFull.append(entry->parts[i].data, entry->parts[i].size);
    }

    // Mark complete
    entry->used = false;
    markSeen(msg_id);

    return true;
}

void drawXbmRotSkew(int16_t xMove, int16_t yMove, int16_t width, int16_t height, const uint8_t *xbm, int16_t degrees)
{
    OLEDDisplay *display = screen->getDisplayDevice();
    // Fixed‑point scale factor
    const int16_t FP = 256;

    // Convert angle to radians (integer-friendly)
    float rad = degrees * 0.01745329251f;

    // Compute shear factors in fixed‑point
    int16_t k1 = (int16_t)(-tan(rad * 0.5f) * FP);
    int16_t k2 = (int16_t)(sin(rad) * FP);

    // Center of image
    int16_t cx = width / 2;
    int16_t cy = height / 2;

    int16_t widthInXbm = (width + 7) / 8;

    for (int16_t y = 0; y < height; y++) {
        for (int16_t x = 0; x < width; x++) {

            // Translate to center
            int16_t dx = x - cx;
            int16_t dy = y - cy;

            // --- 1st shear (X) ---
            int16_t sx1 = dx + ((k1 * dy) >> 8);
            int16_t sy1 = dy;

            // --- 2nd shear (Y) ---
            int16_t sx2 = sx1;
            int16_t sy2 = sy1 + ((k2 * sx1) >> 8);

            // --- 3rd shear (X) ---
            int16_t sx3 = sx2 + ((k1 * sy2) >> 8);
            int16_t sy3 = sy2;

            // Translate back
            int16_t srcX = sx3 + cx;
            int16_t srcY = sy3 + cy;

            // Wrap around
            if (srcX < 0)
                srcX += width;
            if (srcX >= width)
                srcX -= width;
            if (srcY < 0)
                srcY += height;
            if (srcY >= height)
                srcY -= height;

            // Read bit
            int16_t byteIndex = (srcX >> 3) + srcY * widthInXbm;
            uint8_t data = pgm_read_byte(xbm + byteIndex);

            if (data & (1 << (srcX & 7))) {
                display->setPixel(xMove + x, yMove + y);
            }
        }
    }
}

void drawReticule(OLEDDisplay *display, uint32_t center_x, uint32_t center_y, uint32_t width, uint32_t height)
{
    int line_x = width / 4;
    int line_y = height / 4;

    display->drawLine(center_x - (width / 2), center_y - (height / 2), center_x - (width / 2) + line_x, center_y - (height / 2));
    display->drawLine(center_x - (width / 2), center_y - (height / 2), center_x - (width / 2), center_y - (height / 2) + line_y);

    display->drawLine(center_x + (width / 2), center_y - (height / 2), center_x + (width / 2) - line_x, center_y - (height / 2));
    display->drawLine(center_x + (width / 2), center_y - (height / 2), center_x + (width / 2), center_y - (height / 2) + line_y);

    display->drawLine(center_x - (width / 2), center_y + (height / 2), center_x - (width / 2) + line_x, center_y + (height / 2));
    display->drawLine(center_x - (width / 2), center_y + (height / 2), center_x - (width / 2), center_y + (height / 2) - line_y);

    display->drawLine(center_x + (width / 2), center_y + (height / 2), center_x + (width / 2) - line_x, center_y + (height / 2));
    display->drawLine(center_x + (width / 2), center_y + (height / 2), center_x + (width / 2), center_y + (height / 2) - line_y);
}

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

bool ecdsa_sign_atomic(const uint8_t privKey[32], const uint8_t *msg, size_t msgLen,
                       uint8_t *sigOut,   // must be 64 bytes
                       size_t &sigLenOut) // will be set to 64
{
    // 1) Hash the message
    uint8_t digest[32];
    SHA256 sha;
    sha.reset();
    sha.update(msg, msgLen);
    sha.finalize(digest, sizeof(digest));

    mbedtls_ecdsa_context ctx;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "ecdsa_sign_atomic";
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) != 0)
        return false;

    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        return false;

    if (mbedtls_mpi_read_binary(&ctx.d, privKey, 32) != 0)
        return false;

    // Compute public key (optional, but your original code did it)
    if (mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, mbedtls_ctr_drbg_random, &drbg) != 0)
        return false;

    // r and s components
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Produce raw r and s
    if (mbedtls_ecdsa_sign(&ctx.grp, &r, &s, &ctx.d, digest, sizeof(digest), mbedtls_ctr_drbg_random, &drbg) != 0)
        return false;

    // Export r and s as fixed 32‑byte big‑endian values
    if (mbedtls_mpi_write_binary(&r, sigOut, 32) != 0)
        return false;

    if (mbedtls_mpi_write_binary(&s, sigOut + 32, 32) != 0)
        return false;

    sigLenOut = 64;

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    return true;
}

bool ecdsa_verify_atomic(const uint8_t pubKey[65], const uint8_t *msg, size_t msgLen,
                         const uint8_t *sig, // 64 bytes: r||s
                         size_t sigLen)
{
    if (sigLen != 64)
        return false; // must be exactly 32 + 32

    // 1) Hash the message
    uint8_t digest[32];
    SHA256 sha;
    sha.reset();
    sha.update(msg, msgLen);
    sha.finalize(digest, sizeof(digest));

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    // Load curve
    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        return false;

    // Load uncompressed public key (0x04 + X + Y)
    if (mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pubKey, 65) != 0)
        return false;

    // Split signature into r and s
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_mpi_read_binary(&r, sig, 32) != 0)
        return false;

    if (mbedtls_mpi_read_binary(&s, sig + 32, 32) != 0)
        return false;

    // Verify raw r and s
    int ret = mbedtls_ecdsa_verify(&ctx.grp, digest, sizeof(digest), &ctx.Q, &r, &s);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);

    return ret == 0;
}

const std::array<uint8_t, 65> petServerPublicKey = {0x04, 0x03, 0xBA, 0x42, 0x06, 0x2C, 0x03, 0x97, 0x74, 0x91, 0xB6, 0x07, 0x14,
                                                    0xCA, 0x67, 0x8D, 0xD4, 0x16, 0x0E, 0xA7, 0x58, 0xD8, 0xDB, 0xCE, 0x6B, 0x7A,
                                                    0x95, 0x3A, 0xC9, 0x54, 0x9A, 0x7E, 0x6D, 0xB8, 0x64, 0xF5, 0xDC, 0xE5, 0x4E,
                                                    0xD3, 0xE3, 0x37, 0x30, 0x34, 0x9A, 0x2A, 0xC9, 0xD9, 0xCD, 0xCA, 0x0F, 0x10,
                                                    0xBA, 0x15, 0xCB, 0x2C, 0x68, 0xAE, 0xF7, 0x5A, 0xC8, 0x7B, 0xC7, 0x6B, 0x59};

bool verifyPetStatusSignature(const PetStatus &st)
{
    // Maximum canonical size:
    // 1 (version)
    // 65 (pet pubkey)
    // 65 (owner pubkey)
    // 1 + 32 (name length + name)
    // 9 stats
    const size_t max_canon = 1 + 65 + 65 + 1 + 32 + 9;
    uint8_t canon[max_canon];
    size_t pos = 0;

    // version
    canon[pos++] = (uint8_t)st.version;

    // pet_public_key
    if (st.pet_announcement.pet_public_key.size != 65)
        return false;
    memcpy(&canon[pos], st.pet_announcement.pet_public_key.bytes, 65);
    pos += 65;

    // owner_public_key
    if (st.pet_announcement.owner_public_key.size != 65)
        return false;
    memcpy(&canon[pos], st.pet_announcement.owner_public_key.bytes, 65);
    pos += 65;

    // pet_name
    uint8_t nameLen = 0;
    if (st.pet_name != nullptr) {
        nameLen = (uint8_t)strnlen(st.pet_name, 32);
    }
    canon[pos++] = nameLen;
    memcpy(&canon[pos], st.pet_name, nameLen);
    pos += nameLen;

    // stats (9 bytes)
    uint8_t stats[9] = {(uint8_t)st.sp, (uint8_t)st.re, (uint8_t)st.ha, (uint8_t)st.vg, (uint8_t)st.sa,
                        (uint8_t)st.en, (uint8_t)st.jy, (uint8_t)st.ey, (uint8_t)st.sc};
    memcpy(&canon[pos], stats, 9);
    pos += 9;

    // server_sig must be 64 bytes
    if (st.server_sig.size != 64)
        return false;

    // Verify signature
    bool ok = ecdsa_verify_atomic(petServerPublicKey.data(), // 65‑byte uncompressed server pubkey
                                  canon, pos,                // canonical bytes
                                  st.server_sig.bytes,       // r||s
                                  st.server_sig.size);

    return ok;
}

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

// Verify an incoming envelope and extract the payload.
// Returns true if signature is valid and payload is copied out.
bool verifyEnvelope(const PetEnvelope &env, const uint8_t *serverPubKey)
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

    return true;
}

// Decode the inner message after verifying envelope.
// Caller must pass the correct message type.
template <typename T> bool decodeVerifiedPayload(const uint8_t *payload, size_t payloadLen, T &msg, const pb_msgdesc_t *fields)
{
    return decodeProto(msg, fields, payload, payloadLen);
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
    : SinglePortModule("pet", meshtastic_PortNum_STA_PET), concurrency::OSThread("Pet"), currentScreen(PetScreen::Init),
      currentSelection(0)
{
    LOG_INFO("PetModule is enabled");
    // this->inputObserver.observe(inputBroker);

    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
    this->inputObserver.observe(inputBroker);
}

void PetModule::handleInit()
{
    LOG_DEBUG("handleInit");
    textInput = false;
    if (!loadPet()) {
        LOG_DEBUG("Invalid or Missing Pet");
        currentScreen = PetScreen::HatcheryLoad;
        return;
    }

    if (myPet.pet_status.sp < 5) {
        LOG_DEBUG("Egg Species Found");
        currentScreen = PetScreen::EggMenu;
        return;
    }

    if (myPet.pet_status.sp < 10) {
        LOG_DEBUG("Pet Species Found");
        currentScreen = PetScreen::PetMenu;
        return;
    }

    LOG_DEBUG("Unexpected State");
    currentScreen = PetScreen::HatcheryLoad;
    return;
}

void PetModule::handleHatcheryLoad()
{
    LOG_DEBUG("handleHatcheryLoad");
    textInput = false;
    if (!readyA) {
        readyA = ecdsa_generate_keypair_atomic(privOutA, pubOutA);
        spA = getSpecies(pubOutA);
        return;
    }
    if (!readyB) {
        readyB = ecdsa_generate_keypair_atomic(privOutB, pubOutB);
        spB = getSpecies(pubOutB);
        return;
    }
    if (!readyC) {
        readyC = ecdsa_generate_keypair_atomic(privOutC, pubOutC);
        spC = getSpecies(pubOutC);
        return;
    }
    currentScreen = PetScreen::HatcheryMenu;
}

void PetModule::handleHatcheryMenu()
{
    LOG_DEBUG("handleHatcheryMenu");
    textInput = false;
    // Allow selection of Egg
}

void PetModule::handleNameEntry()
{
    LOG_DEBUG("handleNameEntry");
    textInput = true;
}

void PetModule::handleEggMenu()
{
    LOG_DEBUG("handleEggMenu");
    textInput = false;
    // Allow selection of petAction
}

void PetModule::handlePetMenu()
{
    LOG_DEBUG("handlePetMenu");
    textInput = false;
    // Allow selection of petAction
}

void PetModule::setScreen(PetScreen newScreen) {}
void PetModule::nextSelection()
{
    LOG_DEBUG("nextSelection");
    currentSelection += 1;
    screen->runNow();
}
void PetModule::prevSelection()
{
    LOG_DEBUG("prevSelection");
    currentSelection -= 1;
    screen->runNow();
}

bool PetModule::hasValidPet()
{
    return pet_loaded;
}

bool PetModule::loadPet()
{
    prefs.begin("PetModule", false);
    uint8_t stored[512];
    size_t stored_len = prefs.getBytes("pet", stored, 512);
    prefs.end();

    if (stored_len == 0) {
        LOG_DEBUG("No Pet Stored");
        return false;
    }

    if (!decodeProto(myPet, PetRecord_fields, stored, stored_len)) {
        LOG_DEBUG("Couldn't Decode Pet");
        return false;
    }

    if (!(myPet.has_pet_status)) {
        LOG_DEBUG("Missing PetStatus");
        return false;
    }

    if (!(myPet.has_pet_status && myPet.pet_status.has_pet_announcement)) {
        LOG_DEBUG("Missing PetAnnouncement");
        return false;
    }

    uint8_t testsig[128];
    size_t testsig_len = 0;
    const char *testmsg = "testmsg";
    size_t testmsg_len = 7;
    if (!(ecdsa_sign_atomic(myPet.private_key.bytes, (const uint8_t *)testmsg, testmsg_len, testsig, testsig_len) &&
          ecdsa_verify_atomic(myPet.pet_status.pet_announcement.pet_public_key.bytes, (const uint8_t *)testmsg, testmsg_len,
                              testsig, testsig_len))) {
        return false;
    }

    pet_loaded = true;
    return pet_loaded;
}

bool PetModule::savePet()
{
    uint8_t stored[512];
    size_t stored_len = sizeof(stored);

    if (!encodeProto(myPet, PetRecord_fields, stored, sizeof(stored), stored_len))
        return false;

    prefs.begin("PetModule", false);
    prefs.putBytes("record", &myPet, sizeof(myPet));
    prefs.end();
    pet_loaded = true;
    return true;
}

void PetModule::handleSelectEgg()
{
    LOG_DEBUG("handleSelectEgg");
    setScreen(PetScreen::SendSpinner);
    screen->runNow();
    LOG_DEBUG("Creating PetRecord");
    {
        PetRecord tmp = PetRecord_init_default;
        myPet = tmp;
    }
    myPet.has_pet_status = true;
    myPet.pet_status.has_pet_announcement = true;
    LOG_DEBUG("Loading the selected egg into PetRecord");
    switch (currentSelection % 3) {
    case 0:
        memcpy(myPet.private_key.bytes, privOutA, sizeof(privOutA));
        myPet.private_key.size = sizeof(privOutA);
        memcpy(myPet.pet_status.pet_announcement.pet_public_key.bytes, pubOutA, sizeof(pubOutA));
        myPet.pet_status.pet_announcement.pet_public_key.size = sizeof(pubOutA);
        break;
    case 1:
        memcpy(myPet.private_key.bytes, privOutB, sizeof(privOutB));
        myPet.private_key.size = sizeof(privOutB);
        memcpy(myPet.pet_status.pet_announcement.pet_public_key.bytes, pubOutB, sizeof(pubOutB));
        myPet.pet_status.pet_announcement.pet_public_key.size = sizeof(pubOutB);
        break;
    case 2:
        memcpy(myPet.private_key.bytes, privOutC, sizeof(privOutC));
        myPet.private_key.size = sizeof(privOutC);
        memcpy(myPet.pet_status.pet_announcement.pet_public_key.bytes, pubOutC, sizeof(pubOutC));
        myPet.pet_status.pet_announcement.pet_public_key.size = sizeof(pubOutC);
        break;
    }
    myPet.pet_status.pet_announcement.node_id = nodeDB->getNodeNum();
    memcpy(myPet.pet_status.pet_announcement.owner_public_key.bytes, owner.public_key.bytes, owner.public_key.size);
    myPet.pet_status.pet_announcement.owner_public_key.size = owner.public_key.size;
    LOG_DEBUG("Ann Pet Pubkey Size: %i", myPet.pet_status.pet_announcement.pet_public_key.size);
    LOG_DEBUG("Ann Owner Pubkey Size: %i", myPet.pet_status.pet_announcement.owner_public_key.size);
    fragSend(myPet.pet_status.pet_announcement, PetAnnouncement_fields, PetMessageType_PET_MESSAGE_TYPE_ANNOUNCEMENT);
}

int32_t PetModule::runOnce()
{
    if (delayedAction) {
        delayedAction = false;
        return 3000;
    }
    if (interceptingKeyboardInput()) {
        switch (currentScreen) {
        case PetScreen::Init:
            handleInit();
            break;
        case PetScreen::HatcheryLoad:
            handleHatcheryLoad();
            break;
        case PetScreen::HatcheryMenu:
            handleHatcheryMenu();
            break;
        case PetScreen::NameEntry:
            handleNameEntry();
            break;
        case PetScreen::EggMenu:
            handleEggMenu();
            break;
        case PetScreen::PetMenu:
            handlePetMenu();
            break;
        }
        return 1000;
    }
    return 10000;
}

bool PetModule::shouldDraw()
{
    return true;
}

void PetModule::drawFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    switch (currentScreen) {

    case PetScreen::Init:
        display->drawXbm(x + (SCREEN_WIDTH - title_width) / 2, y + (SCREEN_HEIGHT - title_height) / 2, title_width, title_height,
                         title_bits);
        break;

    case PetScreen::HatcheryLoad:
        // Display the Load and Menu elements
        if (readyA) {
            drawXbmPet(display, SCREEN_WIDTH / 4 * 1, SCREEN_HEIGHT / 2, spA);
        } else {
            drawXbmRotSkew(x + ((SCREEN_WIDTH / 4) * 1) - (spinner_width / 2), y + (SCREEN_HEIGHT / 4) - (spinner_height / 2),
                           spinner_width, spinner_height, spinner_bits, rot);
        }
        if (readyB) {
            drawXbmPet(display, SCREEN_WIDTH / 4 * 2, SCREEN_HEIGHT / 2, spB);
        } else {
            drawXbmRotSkew(x + ((SCREEN_WIDTH / 4) * 2) - (spinner_width / 2), y + (SCREEN_HEIGHT / 4) - (spinner_height / 2),
                           spinner_width, spinner_height, spinner_bits, rot + 50);
        }
        if (readyC) {
            drawXbmPet(display, SCREEN_WIDTH / 4 * 3, SCREEN_HEIGHT / 2, spC);
        } else {
            drawXbmRotSkew(x + ((SCREEN_WIDTH / 4) * 3) - (spinner_width / 2), y + (SCREEN_HEIGHT / 4) - (spinner_height / 2),
                           spinner_width, spinner_height, spinner_bits, rot + 120);
        }
        rot += 360 - 40;
        rot %= 360;
        screen->runNow();
        break;

    case PetScreen::HatcheryMenu:
        // Display the Load and Menu elements
        drawXbmPet(display, SCREEN_WIDTH / 4 * 1, SCREEN_HEIGHT / 2, spA);
        drawXbmPet(display, SCREEN_WIDTH / 4 * 2, SCREEN_HEIGHT / 2, spB);
        drawXbmPet(display, SCREEN_WIDTH / 4 * 3, SCREEN_HEIGHT / 2, spC);
        drawReticule(display, SCREEN_WIDTH / 4 * ((currentSelection % 3) + 1), SCREEN_HEIGHT / 2, 32, 32);
        break;

    case PetScreen::SendSpinner:
        // Display the Load and Menu elements
        drawXbmRotSkew((SCREEN_WIDTH - spinner_width) / 2, (SCREEN_HEIGHT - spinner_height) / 2, spinner_width, spinner_height,
                       spinner_bits, rot + 120);
        rot += 360 - 40;
        rot %= 360;
        screen->runNow();
        break;

    case PetScreen::NameEntry:
        display->setFont(ArialMT_Plain_10);
        // Left: name + menu
        display->drawString(0, 0, "Name your egg...");
        display->drawString(0, 0, nameBuf);
        break;

    case PetScreen::EggMenu:
        display->setFont(ArialMT_Plain_10);

        // Left: name + menu
        display->drawString(0, 0, myPet.pet_status.pet_name);

        for (int i = 0; i < eggMenuCount; ++i) {
            int y = 12 + i * 10;
            if (i == currentSelection) {
                // draw pointer (8x8 empty XBM for now)
                display->drawXbm(0, y, cursor_width, cursor_height, cursor_bits);
            }
            display->drawString(12, y, eggMenuItems[i]);
            drawXbmPet(display, SCREEN_WIDTH / 4 * 3, SCREEN_HEIGHT / 2, myPet.pet_status.sp);
        }

        break;

    case PetScreen::PetMenu:
        display->setFont(ArialMT_Plain_10);

        // Left: name + menu
        display->drawString(0, 0, myPet.pet_status.pet_name);

        for (int i = 0; i < petMenuCount; ++i) {
            int y = 12 + i * 10;
            if (i == currentSelection) {
                // draw pointer (8x8 empty XBM for now)
                display->drawXbm(0, y, cursor_width, cursor_height, cursor_bits);
            }
            display->drawString(12, y, petMenuItems[i]);
            drawXbmPet(display, SCREEN_WIDTH / 4 * 3, SCREEN_HEIGHT / 2, myPet.pet_status.sp);
        }
        break;

    case PetScreen::PetStats: {
        const auto &st = myPet.pet_status;
        int maxBar = 60;

        auto drawBar = [&](int y, const char *label, uint8_t value, uint8_t cap) {
            display->drawString(0, y, label);
            float f = cap ? (float)value / (float)cap : 0.0f;
            if (f > 1.0f)
                f = 1.0f;
            int w = (int)(f * maxBar);
            display->drawRect(30, y, maxBar, 8);
            display->fillRect(30, y, w, 8);
        };

        display->setFont(ArialMT_Plain_10);

        // Left: name + menu
        display->drawString(0, 0, myPet.pet_status.pet_name);
        drawBar(12, "Sat", st.sa, (20 + (2 * (st.vg + st.re)))); // or some derived cap
        drawBar(24, "Enc", st.en, st.re);
        drawBar(36, "Joy", st.jy, st.ha);
        drawBar(48, "Eng", st.ey, st.vg);
    } break;
    }

    /* display->drawXbm(x + (SCREEN_WIDTH - icon_width) / 2, y + (SCREEN_HEIGHT - FONT_HEIGHT_MEDIUM - icon_height) / 2 + 2 +
       10, icon_width, icon_height, icon_bits); */
}

void PetModule::sendNameAction()
{
    if (!hasValidPet())
        return;

    setScreen(PetScreen::SendSpinner);
    screen->runNow();
    PetAction act = PetAction_init_default;
    act.version = 1;

    // embed last known time + status
    // (you can keep last timesignal + status in myPet or separate fields)
    act.time_signal = last_timesignal; // if you store it
    act.pet_status = myPet.pet_status;

    act.verb = PetVerb_NAME;

    // extra = name string
    std::string nameStr = nameBuf.c_str();
    if (nameStr.size() > 32)
        nameStr.resize(32);
    act.extra.size = nameStr.size();
    memcpy(act.extra.bytes, nameStr.data(), nameStr.size());

    act.nonce += 1;

    // Wrap in PetEnvelope, sign, fragment, send
    fragSend(act, PetAction_fields, PetMessageType_PET_MESSAGE_TYPE_ACTION);
}

int PetModule::handleInputEvent(const InputEvent *event)
{
    if (interceptingKeyboardInput()) {
        LOG_DEBUG("FlagInput: %i -> Event %i (Char %c)", event->source, event->inputEvent, event->kbchar);
        if (textInput) {
            LOG_DEBUG("Pet Textmode, Only Supposed to Happen in NameEntry");
            if (currentScreen == PetScreen::NameEntry) {
                // Simple: ENTER = submit, CANCEL = hatchery, BACK = backspace
                if (event->inputEvent == INPUT_BROKER_CANCEL) {
                    // maybe go back to HatcheryMenu
                    setScreen(PetScreen::HatcheryMenu);
                }
                if (event->inputEvent == INPUT_BROKER_BACK && nameBuf.length() > 0) {
                    nameBuf.remove(nameBuf.length() - 1);
                }
                if (event->inputEvent == INPUT_BROKER_SELECT) {
                    // submit name: build NAME PetAction
                    // name is in some buffer, e.g. nameBuffer
                    sendNameAction();
                    // show spinner until PetStatus comes back
                    delayedAction = true;
                    return 1;
                }
                if (event->kbchar >= 32 && event->kbchar <= 126 && nameBuf.length() > 32) {
                    // append to name buffer (max 32)
                    nameBuf.concat(event->kbchar);
                    return 1;
                }
            }
        } else {
            LOG_DEBUG("Pet Cursormode");
            if (event->inputEvent == INPUT_BROKER_UP ||
                (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("2abcABC", event->kbchar))) {
                LOG_DEBUG("Up Action");
                prevSelection();
            } else if (event->inputEvent == INPUT_BROKER_DOWN ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("8tuvTUV", event->kbchar))) {
                LOG_DEBUG("Down Action");
                nextSelection();
            } else if (event->inputEvent == INPUT_BROKER_LEFT ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("4ghiGHI", event->kbchar))) {
                LOG_DEBUG("Left Action");
                prevSelection();
            } else if (event->inputEvent == INPUT_BROKER_RIGHT ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("6mnoMNO", event->kbchar))) {
                LOG_DEBUG("Right Action");
                nextSelection();
            } else if (event->inputEvent == INPUT_BROKER_SELECT) {
                LOG_DEBUG("Select Action");
                switch (currentScreen) {
                case PetScreen::HatcheryMenu:
                    handleSelectEgg();
                    break;
                default:
                    break;
                }
            } else if (event->inputEvent == INPUT_BROKER_USER_PRESS) {
                screen->showNextFrame();
            } else if (event->inputEvent == INPUT_BROKER_CANCEL) {
                screen->showPrevFrame();
            }
        }
        // If this module receives a input event, then don't allow it to flow to other listeners.
        return 1;
    }
    return 0; // If this module receives a input event, then don't allow it to flow to other listeners.
}

bool PetModule::interceptingKeyboardInput()
{
    MeshModule *focused = screen ? screen->getFocusedModule() : nullptr;
    return (this->enabled && focused == this);
}

ProcessMessage PetModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (mp.decoded.portnum != meshtastic_PortNum_STA_PET)
        return ProcessMessage::CONTINUE;
    LOG_DEBUG("PetModule received STA_PET packet!");

    const auto &payload = mp.decoded.payload;

    LOG_DEBUG("Attempting to decode as a fragment");
    PetFragment frag = PetFragment_init_default;

    if (!pb_decode_from_bytes(payload.bytes, payload.size, PetFragment_fields, &frag)) {
        LOG_WARN("PetModule: couldn't decode PetFragment");
        return ProcessMessage::STOP;
    }

    if (frag.magic != 0x50455446) {
        LOG_WARN("PetModule: bad magic");
        return ProcessMessage::STOP;
    }

    std::string full;
    if (!processFragment(frag, full)) {
        // waiting for more or already processed
        return ProcessMessage::STOP;
    }

    // Now we have a full PetEnvelope
    PetEnvelope env = PetEnvelope_init_default;

    if (!pb_decode_from_bytes((const uint8_t *)full.data(), full.size(), PetEnvelope_fields, &env)) {
        LOG_WARN("PetModule: couldn't decode PetEnvelope");
        return ProcessMessage::STOP;
    }

    if (env.message_type == PetMessageType_PET_MESSAGE_TYPE_TIME_SIGNAL) {
        LOG_WARN("PetModule: Processing as a Time Signal");
        if (!verifyEnvelope(env, petServerPublicKey.data())) {
            LOG_WARN("PetModule: couldn't verify envelope signature");
            return ProcessMessage::STOP;
        }

        PetTimeSignal ts = PetTimeSignal_init_default;
        if (pb_decode_from_bytes(env.payload.bytes, env.payload.size, PetTimeSignal_fields, &ts)) {
            last_timesignal.unix_time_s = ts.unix_time_s;
            LOG_DEBUG("PetModule: Current time: %i", ts.unix_time_s);
        } else {
            LOG_WARN("PetModule: couldn't decode PetTimeSignal");
        }
        return ProcessMessage::STOP;
    }

    if (env.message_type == PetMessageType_PET_MESSAGE_TYPE_STATUS) {
        LOG_WARN("PetModule: Processing as a Pet Status");
        if (!verifyEnvelope(env, petServerPublicKey.data())) {
            LOG_WARN("PetModule: couldn't verify envelope signature");
            return ProcessMessage::STOP;
        }

        PetStatus status = PetStatus_init_default;
        if (!pb_decode_from_bytes(env.payload.bytes, env.payload.size, PetStatus_fields, &status)) {
            LOG_WARN("PetModule: couldn't decode PetStatus");
            return ProcessMessage::STOP;
        }

        if (!status.has_pet_announcement ||
            status.pet_announcement.pet_public_key.bytes != myPet.pet_status.pet_announcement.pet_public_key.bytes) {
            LOG_DEBUG("PetModule: not my monkey");
            return ProcessMessage::STOP;
        }

        if (!verifyPetStatusSignature(status)) {
            LOG_WARN("PetModule: couldn't verify PetStatus signature");
            return ProcessMessage::STOP;
        }

        // Store into myPet + prefs
        myPet.pet_status = status; // assuming PetRecord has pet_status field
        nameBuf = String(myPet.pet_status.pet_name);
        savePet();

        // Mark that we now have a valid pet and can move UI forward
        handlePetUpdate();

        return ProcessMessage::STOP;
    }

    LOG_WARN("PetModule: ignoring non-status and non-ts messages");
    return ProcessMessage::STOP;
}

template <typename T> void PetModule::fragSend(const T &msg, const pb_msgdesc_t *fields, PetMessageType pet_message_type)
{
    LOG_DEBUG("Serializing the message...");
    size_t msg_len = sizeof(frag_msg_buffer);
    msg_len = pb_encode_to_bytes(frag_msg_buffer, sizeof(frag_msg_buffer), fields, &msg);
    if (msg_len == 0) {
        LOG_DEBUG("Couldn't serialize the message");
        return;
    }
    LOG_DEBUG("Serialized the message (%i bytes)", msg_len);
    LOG_DEBUG("Creating the envelope");
    PetEnvelope signedMsg = PetEnvelope_init_default;
    signedMsg.message_type = pet_message_type;
    memcpy(signedMsg.payload.bytes, frag_msg_buffer, msg_len);
    signedMsg.payload.size = msg_len;
    memcpy(signedMsg.public_key.bytes, myPet.pet_status.pet_announcement.pet_public_key.bytes,
           myPet.pet_status.pet_announcement.pet_public_key.size);
    signedMsg.public_key.size = myPet.pet_status.pet_announcement.pet_public_key.size;
    LOG_DEBUG("Signing the message");
    size_t sigOutLen = sizeof(frag_sigOut);
    if (!ecdsa_sign_atomic(myPet.private_key.bytes, frag_msg_buffer, msg_len, frag_sigOut, sigOutLen)) {
        LOG_DEBUG("Couldn't sign the Pet Announcement");
        return;
    }
    if (sigOutLen != 64) {
        LOG_DEBUG("Unexpected signature length: %u", (unsigned)sigOutLen);
        return;
    }
    LOG_DEBUG("Announcement signed");
    memcpy(signedMsg.signature.bytes, frag_sigOut, sigOutLen);
    signedMsg.signature.size = sigOutLen;
    LOG_DEBUG("SigAnn MsgType: %i", signedMsg.message_type);
    LOG_DEBUG("SigAnn Payload Size: %i", signedMsg.payload.size);
    LOG_DEBUG("SigAnn Pubkey Size: %i", signedMsg.public_key.size);
    LOG_DEBUG("SigAnn Signature Size: %i", signedMsg.signature.size);
    LOG_DEBUG("Serializing the envelope...");
    size_t envOutLen = sizeof(frag_envOut);
    envOutLen = pb_encode_to_bytes(frag_envOut, sizeof(frag_envOut), PetEnvelope_fields, &signedMsg);
    if (envOutLen == 0) {
        LOG_DEBUG("Couldn't serialize the envelope");
        return;
    }
    LOG_DEBUG("Serialized the envelope (%i bytes)", envOutLen);
    // LOG_DEBUG("Didn't panic while serialising the envelope");
    // LOG_DEBUG("Building the Signed Pet Announcement");
    //  buildSignedPetAnnouncement(myPet.private_key.bytes, myPet.pet_status.pet_announcement.pet_public_key.bytes,
    //                             myPet.pet_status.pet_announcement.owner_public_key.bytes, announce_buffer, 512,
    //                             announce_len);

    // for (int i = 0; i < 3; i++) {

    const size_t FRAG_SIZE = 150; // safe for Meshtastic MTU

    uint32_t msg_id = hashDerivedInt(UINT32_MAX, frag_envOut, envOutLen);
    size_t fragment_count = (envOutLen + FRAG_SIZE - 1) / FRAG_SIZE;

    for (size_t i = 0; i < fragment_count; i++) {
        PetFragment frag = PetFragment_init_default;
        frag.magic = 0x50455446;
        frag.msg_id = msg_id;
        frag.fragment_index = i;
        frag.fragment_count = fragment_count;

        size_t offset = i * FRAG_SIZE;
        size_t len = std::min(FRAG_SIZE, envOutLen - offset);

        memcpy(frag.data.bytes, frag_envOut + offset, len);
        frag.data.size = len;

        // Encode frag into a buffer
        size_t fragLen = pb_encode_to_bytes(fragBuf, sizeof(fragBuf), PetFragment_fields, &frag);

        // Send fragBuf as the payload of a MeshPacket

        LOG_DEBUG("Getting a Datapacket from Pool");
        meshtastic_MeshPacket *p = allocDataPacket();
        // Not setting "to", Broadcast.
        p->to = 0xffffffff;
        // Not setting "channel", Primary
        p->want_ack = false;
        LOG_DEBUG("Copy envOut into packet payload");
        memcpy(p->decoded.payload.bytes, fragBuf, fragLen);
        p->decoded.payload.size = fragLen;
        LOG_DEBUG("Sending packet");
        service->sendToMesh(p, RX_SRC_LOCAL, true);
    }
}

void PetModule::handlePetUpdate()
{
    LOG_DEBUG("Received a Pet Status for us");
    // Called after we receive a PetStatus and store it
    if (!hasValidPet())
        LOG_DEBUG("The pet was malformed");
    return;

    // If we don't have a name yet (or still default), go to NameEntry
    LOG_DEBUG("Checking pet name: %s", myPet.pet_status.pet_name);
    if (new_pet) {
        setScreen(PetScreen::NameEntry);
    } else {
        // We already have a name, go straight to egg or pet menu
        if (myPet.pet_status.sp <= 4) {
            setScreen(PetScreen::EggMenu);
        } else {
            setScreen(PetScreen::PetMenu);
        }
    }
}
