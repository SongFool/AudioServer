#include "config.h"
#ifdef SUPPORT_AUDIO
#ifndef __DW_AUDIO_H__
#define __DW_AUDIO_H__
#include "gd32l23x.h"
#include "base_types.h"

extern u32 AUDIO_ADDR;
typedef enum {
    Audio_Text = 0,
    Audio_Power_Low_Charging,
    Audio_Power_Low,
    Audio_Welcome,
    Audio_Start_Charging,
    Audio_Hum_Alarm,
    Audio_Net_Waek,
    Audio_Temp_Alarm,
    Audio_Wifi_Connect_Fail,
    Audio_Wifi_Connect,
    Audio_Wifi_Weak,
    Audio_Wifi_Disconnect,
    Audio_Start_wifi,
    Audio_Update,
    Audio_Usb_disconnect,
    Audio_MAX,
}audio_list;
typedef struct _audio_info{
    uint8_t *buffer[2];
    volatile uint8_t current_index_buf; 
    uint32_t size;
    uint32_t play_addr;
    uint32_t play_stop_addr;
    uint32_t play_len;
}audio_info;

typedef struct{
    audio_list id;
    uint32_t len;
    uint32_t src_addr;
}music_data;

typedef struct{
    uint8_t* p_flash_data;;
    uint32_t audio_write_addr;
    uint16_t flash_addr;
    uint8_t circulation;
}Audio_factory;

void audio_factory_fun(char * cmd_str);
void audio_play(audio_list id);
void audio_factory_set_circulation(uint8_t value);
void audio_delay_play(void);
void audio_play_usb_disconnect(void);
bool get_audio_factory_status(void);
void set_audio_factory_status(bool status);
#endif /*__DW_AUDIO_H__*/
#endif /*SUPPORT_AUDIO*/
