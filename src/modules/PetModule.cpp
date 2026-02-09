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

#define SCREEN_WIDTH display->getWidth()
#define SCREEN_HEIGHT display->getHeight()

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
    : SinglePortModule("pet", meshtastic_PortNum_STA_PET), concurrency::OSThread("Pet"), currentScreen(PetScreen::Init),
      currentSelection(0)
{
    LOG_INFO("PetModule is enabled");
    // this->inputObserver.observe(inputBroker);
    prefs.begin("PetModule", false);
    UIFrameEvent e;
    e.action = UIFrameEvent::Action::REGENERATE_FRAMESET_BACKGROUND; // We want to change the list of frames shown on-screen
    this->notifyObservers(&e);
    this->inputObserver.observe(inputBroker);
}

void PetModule::handleInit()
{
    textInput = false;
    if (!hasValidPet()) {
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
    textInput = false;
    delayedAction = true;
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
    textInput = false;
    // Allow selection of Egg
}

void PetModule::handleNameEntry()
{
    textInput = true;
}

void PetModule::handleEggMenu()
{
    textInput = false;
    // Allow selection of petAction
}

void PetModule::handlePetMenu()
{
    textInput = false;
    // Allow selection of petAction
}

void PetModule::setScreen(PetScreen newScreen) {}
void PetModule::nextSelection()
{
    currentSelection += 1;
    screen->runNow();
}
void PetModule::prevSelection()
{
    currentSelection -= 1;
    screen->runNow();
}

bool PetModule::hasValidPet()
{
    uint8_t stored[256];
    int stored_len = prefs.getBytes("pet", stored, 256);

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

    return true;
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

    /* display->drawXbm(x + (SCREEN_WIDTH - icon_width) / 2, y + (SCREEN_HEIGHT - FONT_HEIGHT_MEDIUM - icon_height) / 2 + 2 +
       10, icon_width, icon_height, icon_bits); */
}

int PetModule::handleInputEvent(const InputEvent *event)
{
    if (interceptingKeyboardInput()) {
        LOG_DEBUG("FlagInput: %i -> Event %i (Char %c)", event->source, event->inputEvent, event->kbchar);
        if (textInput) {
            LOG_DEBUG("TODO: Pet Textmode");
        } else {
            if (event->inputEvent == INPUT_BROKER_UP ||
                (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("2abcABC", event->kbchar))) {
                prevSelection();
            } else if (event->inputEvent == INPUT_BROKER_DOWN ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("8tuvTUV", event->kbchar))) {
                nextSelection();
            } else if (event->inputEvent == INPUT_BROKER_LEFT ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("4ghiGHI", event->kbchar))) {
                prevSelection();
            } else if (event->inputEvent == INPUT_BROKER_RIGHT ||
                       (event->inputEvent == INPUT_BROKER_ANYKEY && strchr("6mnoMNO", event->kbchar))) {
                nextSelection();
            } else if (event->inputEvent == INPUT_BROKER_SELECT) {
                switch (currentScreen) {
                case PetScreen::HatcheryMenu:
                    myPet = PetRecord_init_default;
                    myPet.has_pet_status = true;
                    myPet.pet_status.has_pet_announcement = true;
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
                    memcpy(myPet.pet_status.pet_announcement.owner_public_key.bytes, owner.public_key.bytes,
                           owner.public_key.size);
                    myPet.pet_status.pet_announcement.owner_public_key.size = owner.public_key.size;
                    uint8_t announce_buffer[512];
                    size_t announce_len;
                    if (!sendPetAnnouncement(myPet.private_key.bytes, myPet.pet_status.pet_announcement.pet_public_key.bytes,
                                             myPet.pet_status.pet_announcement.owner_public_key.bytes, announce_buffer, 512,
                                             announce_len)) {
                        return 1;
                    }
                    meshtastic_MeshPacket *p = allocDataPacket(); // Automagic Pet port binding
                    // Not setting "to", Broadcast.
                    // Not setting "channel", Primary
                    p->want_ack = false;
                    memcpy(p->decoded.payload.bytes, announce_buffer, announce_len);
                    p->decoded.payload.size = announce_len;
                    service->sendToMesh(p, RX_SRC_LOCAL, true);
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
    if (mp.decoded.portnum == meshtastic_PortNum_STA_PET) {
        LOG_INFO("Saw a Pet packet!");
        return ProcessMessage::STOP;
    } else {
        return ProcessMessage::CONTINUE;
    }
}
