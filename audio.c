#include "config.h"
#ifdef SUPPORT_AUDIO
#include "dw_audio.h"
#include "stdlib.h"
#include "bsp.h"
#include "flash.h"
#include "stdio.h"
#include <string.h>
#include "log.h"
#include "dw_flash.h"
#include "hw_utils.h"
#include "tstask.h"
#include "dw_charge.h"
#include "dw_led.h"
#include "system.h"

#ifdef AUDIO_DEBUG
#else
#undef logd
#define logd(fmt, ...)
#endif

#define READ                0x03     /* read from memory instruction */
#define DUMMY_BYTE          0xA5
#define AUDIO_SECTOR_SIZE   4096

#define  AUDIO_WRITE_DATA   ("AT+AUDIO:")
#define  AUDIO_WRITE_STOP   ("AT+AUDIOSTOP:")
#define  WRITE_MAX_BYTE     (50)


u32 AUDIO_ADDR = 0;
u8 spi_tx = DUMMY_BYTE;
bool audio_factory_status = false;
uint16_t audio_buffer[2][512];
void audio_play_fun(audio_list id);
audio_info audio_data = {
    .buffer =  
{ (uint8_t *)audio_buffer[0], (uint8_t *)audio_buffer[1] },
    .current_index_buf = 0,     // 当前写入缓冲区索引 (0/1)         // 缓冲区满标志
    .size = 1024,
    .play_addr = 0,
    .play_stop_addr = 0,
    .play_len = 0,
};
Audio_factory audio_factory={
    .p_flash_data = NULL,
    .audio_write_addr = 0,
    .flash_addr = 0,
    .circulation = 0,
};
#ifdef SPEED_8K
const music_data tab[] = 
{
    {0,36864 ,0},                //18820 *2
    {1,67584 ,18825 *2},         //34160 *2
    {2,54272 ,34150 * 2 + 18825 *2},
    {3,45056 ,27250 * 2 + 34150 * 2 + 18825 *2},
    {4,53248 ,22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {5,48128 ,27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {6,53248 ,24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {7,76800 ,26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {8,44032 ,38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {9,49152 ,22300 * 2 + 38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {10,73728,24850 * 2 + 22300 * 2 + 38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {11,56320,37125 * 2 + 24850 * 2 + 22300 * 2 + 38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {12,53248,28400 * 2 + 37125 * 2 + 24850 * 2 + 22300 * 2 + 38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
    {13,53248,26875 * 2 + 28400 * 2 + 37125 * 2 + 24850 * 2 + 22300 * 2 + 38850 * 2 + 26850 * 2 + 24250 * 2 + 27000 * 2 + 22600 * 2 + 27250 * 2 + 34150 * 2 + 18825 *2},
};
#else
const music_data tab[] = 
{
    {0,36864 ,0},                
    {1,136192 ,18825 *2}, 
    {2,51712  ,18825 * 2},         
    {3,108544 ,68300 * 2 + 18825 *2}, 
    {4,90112  ,54400 * 2 + 68300 * 2 + 18825 *2}, 
    {5,107520 ,45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {6,96256  ,54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {7,106496 ,48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {8,154624 ,53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {9,88064  ,77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {10,98340  ,44500 * 2 + 77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {11,147456 ,49600 * 2 + 44500 * 2 + 77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2}, 
    {12,112640 ,74200 * 2 + 49600 * 2 + 44500 * 2 + 77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2},
    {13,106496 ,56800 * 2 + 74200 * 2 + 49600 * 2 + 44500 * 2 + 77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2},
    {14,113664 ,53700 * 2 + 56800 * 2 + 74200 * 2 + 49600 * 2 + 44500 * 2 + 77600 * 2 + 53600 * 2 + 48400 * 2 + 54000 * 2 + 45200 * 2 + 54400 * 2 + 68300 * 2 + 18825 *2},
};
#endif

void audio_speaker_init()
{
    gpio_init_and_set(AUDIO_SPK_EN_RCU, AUDIO_SPK_EN_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, AUDIO_SPK_EN_PIN, 1);
    gpio_init_and_set(AUDIO_SPK_PWR_RCU, AUDIO_SPK_PWR_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, AUDIO_SPK_PWR_PIN, 0);
}
void audio_speaker_deinit()
{
    gpio_init_and_set(AUDIO_SPK_EN_RCU, AUDIO_SPK_EN_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, AUDIO_SPK_EN_PIN, 0);
    gpio_init_and_set(AUDIO_SPK_PWR_RCU, AUDIO_SPK_PWR_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, AUDIO_SPK_PWR_PIN, 1);
}
void audio_dac_config_init(void)
{
    /* enable the clock of peripherals */
    rcu_periph_clock_enable(AUDIO_OUT_RCU);
    rcu_periph_clock_enable(AUDIO_DAC_RCU);
    /* configure PA4 as DAC output */
    gpio_mode_set(AUDIO_OUT_PORT, GPIO_MODE_ANALOG, GPIO_PUPD_NONE, AUDIO_OUT_PIN);
    /* initialize DAC */
    dac_deinit();
    /* DAC trigger disable */
    // dac_trigger_disable();
    dac_trigger_source_config(DAC_TRIGGER_T5_TRGO);
    /* DAC wave mode config */
    dac_wave_mode_config( DAC_WAVE_DISABLE);

    /* DAC output buffer enable */
    dac_output_buffer_enable();
    /* DAC enable */
    dac_enable();
    dac_trigger_disable();
    dac_data_set(DAC_ALIGN_12B_R, 0x7FF);
    dac_trigger_enable();
    /* DAC的DMA功能使能 */
    dac_dma_enable();
    
}
void audio_timer_config_init(void)
{
    timer_parameter_struct timer_initpara;
    rcu_periph_clock_enable(RCU_TIMER5);
    timer_deinit(TIMER5);

    // 初始化定时器
    timer_struct_para_init(&timer_initpara);
    timer_initpara.prescaler = 7;   // 设置预分频值，保证定时器频率为 1kHz
    #ifdef SPEED_8K
    timer_initpara.period = 999;       // 设置周期为 1000ms，即每 1ms 触发一次
    #else
    timer_initpara.period = 999 / 2;
    #endif
    timer_initpara.alignedmode = TIMER_COUNTER_EDGE;
    timer_initpara.counterdirection = TIMER_COUNTER_UP;
    timer_initpara.clockdivision = TIMER_CKDIV_DIV1;
    timer_init(TIMER5, &timer_initpara);

    // 使能定时器溢出中断，产生触发信号
    timer_enable(TIMER5);

    // 设置更新事件为触发源
    timer_master_output_trigger_source_select(TIMER5, TIMER_TRI_OUT_SRC_UPDATE);
    //启动定时器更新事件
    timer_update_event_enable(TIMER5);
    // 使能定时器 DMA 请求
    timer_dma_enable(TIMER5, TIMER_DMA_UPD);

}
void audio_dma_config_init(uint16_t* buffer,u32 len) {
    dma_parameter_struct dma_initpara;
    rcu_periph_clock_enable(RCU_DMA);
    // DMA 通道 0 初始化
    dma_deinit(DMA_CH0);
    dma_struct_para_init(&dma_initpara);
    dma_initpara.request = DMA_REQUEST_TIMER5_UP;   // 设置 DMA 请求源为 TIMER5 溢出触发
    dma_initpara.direction = DMA_MEMORY_TO_PERIPHERAL;   // 从内存传输到外设
    dma_initpara.memory_addr = (uint32_t)buffer;       // 设置数据缓冲区地址
    dma_initpara.memory_inc = DMA_MEMORY_INCREASE_ENABLE; // 启用内存地址递增
    dma_initpara.memory_width = DMA_MEMORY_WIDTH_16BIT;    // 设置内存数据宽度为 16 位
    dma_initpara.number = len;                 // 设置传输的数据大小
    dma_initpara.periph_addr = (uint32_t)&OUT_R12DH; // 设置外设地址
    dma_initpara.periph_inc = DMA_PERIPH_INCREASE_DISABLE; // 外设地址不递增
    dma_initpara.periph_width = DMA_PERIPHERAL_WIDTH_16BIT;   // 设置外设数据宽度为 16 位
    dma_initpara.priority = DMA_PRIORITY_ULTRA_HIGH;        // 设置 DMA 优先级为超高

    dma_init(DMA_CH0, &dma_initpara);
    dmamux_synchronization_disable(DMAMUX_MUXCH0);
    dma_channel_enable(DMA_CH0);
    //dma_circulation_enable(DMA_CH0);
    dma_interrupt_enable(DMA_CH0, DMA_INT_FTF);
    nvic_irq_enable(DMA_Channel0_IRQn, 1); // 设置 DMA0 中断优先级为 2
}
void audio_init(void)
{
    audio_speaker_init();
    audio_dac_config_init();
    audio_timer_config_init();
}
void audio_play_task(){}



void audio_deinit(void)
{
    dac_trigger_disable();
    timer_disable(TIMER5);          
    timer_deinit(TIMER5);        
    dac_dma_disable();     
    dac_disable();                  
    gpio_mode_set(AUDIO_OUT_PORT, GPIO_MODE_INPUT, GPIO_PUPD_PULLDOWN, AUDIO_OUT_PIN); 
    audio_speaker_deinit();
    CurRun.audio_dma_run = false;
    TS_DelTask_by_func(audio_play_task);
}
void spi_rx_flash_dma_config(u8* buffer,u32 len)
{
    dma_parameter_struct dma_initpara;
    rcu_periph_clock_enable(RCU_DMA);
    // DMA 通道 0 初始化
    dma_deinit(DMA_CH1);
    dma_struct_para_init(&dma_initpara);
    dma_initpara.request = DMA_REQUEST_SPI1_RX;   // 设置 DMA 请求源为 SPI1_RX
    dma_initpara.direction = DMA_PERIPHERAL_TO_MEMORY;   // 从外设传输到内存
    dma_initpara.memory_addr = (uint32_t)buffer;       // 设置数据缓冲区地址
    dma_initpara.memory_inc = DMA_MEMORY_INCREASE_ENABLE; // 启用内存地址递增
    dma_initpara.memory_width = DMA_MEMORY_WIDTH_8BIT;    // 设置内存数据宽度为 8 位
    dma_initpara.number = len;                 // 设置传输的数据大小
    dma_initpara.periph_addr = (uint32_t)&SPI_DATA(FLASH_SPI); // 设置外设地址
    dma_initpara.periph_inc = DMA_PERIPH_INCREASE_DISABLE; // 外设地址不递增
    dma_initpara.periph_width = DMA_PERIPHERAL_WIDTH_16BIT;   // 设置外设数据宽度为 16 位
    dma_initpara.priority = DMA_PRIORITY_ULTRA_HIGH;        // 设置 DMA 优先级为超高

    dma_init(DMA_CH1, &dma_initpara);
    dmamux_synchronization_disable(DMAMUX_MUXCH1);
    dma_channel_enable(DMA_CH1);
    //dma_interrupt_enable(DMA_CH1, DMA_INT_FTF);
    nvic_irq_enable(DMA_Channel1_IRQn, 2); // 设置 DMA0 中断优先级为 2
}
void spi_tx_flash_dma_config(u8* buffer,u32 len)
{
    dma_parameter_struct dma_initpara;
    rcu_periph_clock_enable(RCU_DMA);
    // DMA 通道 0 初始化
    dma_deinit(DMA_CH2);
    dma_struct_para_init(&dma_initpara);
    dma_initpara.request = DMA_REQUEST_SPI1_TX;   // 设置 DMA 请求源为 SPI1_RX
    dma_initpara.direction = DMA_MEMORY_TO_PERIPHERAL;   // 从内存到外设
    dma_initpara.memory_addr = (uint32_t)buffer;       // 设置数据缓冲区地址
    dma_initpara.memory_inc = DMA_MEMORY_INCREASE_DISABLE; // 启用内存地址不递增
    dma_initpara.memory_width = DMA_MEMORY_WIDTH_8BIT;    // 设置内存数据宽度为 8 位
    dma_initpara.number = len;                 // 设置传输的数据大小
    dma_initpara.periph_addr = (uint32_t)&SPI_DATA(FLASH_SPI); // 设置外设地址
    dma_initpara.periph_inc = DMA_PERIPH_INCREASE_DISABLE; // 外设地址不递增
    dma_initpara.periph_width = DMA_PERIPHERAL_WIDTH_16BIT;   // 设置外设数据宽度为 16 位
    dma_initpara.priority = DMA_PRIORITY_ULTRA_HIGH;        // 设置 DMA 优先级为超高

    dma_init(DMA_CH2, &dma_initpara);
    dmamux_synchronization_disable(DMAMUX_MUXCH2);
    dma_channel_enable(DMA_CH2);
    //dma_circulation_enable(DMA_CH2);
    //dma_interrupt_enable(DMA_CH2, DMA_INT_HTF); // 启用传输半完成中断
    //nvic_irq_enable(DMA_Channel2_IRQn, 2); // 设置 DMA0 中断优先级为 2
}

void spi_flash_dam_rx_tx_read_init(uint8_t *pbuffer, uint32_t read_addr, uint16_t num_byte_to_read,u8 int_flag){

    spi_rx_flash_dma_config(pbuffer,num_byte_to_read);
    spi_tx_flash_dma_config(&spi_tx,num_byte_to_read);
    if(int_flag == true){
        dma_interrupt_enable(DMA_CH1, DMA_INT_FLAG_FTF);
    }
    /* select the flash: chip slect low */
    SPI_FLASH_CS_LOW();

    /* send "read from memory " instruction */
    spi_flash_send_byte(READ);

    /* send read_addr high nibble address byte to read from */
    spi_flash_send_byte((read_addr & 0xFF0000) >> 16);
    /* send read_addr medium nibble address byte to read from */
    spi_flash_send_byte((read_addr & 0xFF00) >> 8);
    /* send read_addr low nibble address byte to read from */
    spi_flash_send_byte(read_addr & 0xFF);
    spi_dma_enable(FLASH_SPI,SPI_DMA_RECEIVE);
    spi_dma_enable(FLASH_SPI,SPI_DMA_TRANSMIT);

}
void spi_flash_dam_disable(void)
{
    SPI_FLASH_CS_HIGH();
    spi_dma_disable(FLASH_SPI,SPI_DMA_RECEIVE);
    spi_dma_disable(FLASH_SPI,SPI_DMA_TRANSMIT);
}
void DMA_Channel0_IRQHandler(void){
    #ifdef SUPPORT_AGING_TEST
    static u8 index = 1;
    #endif
    if (dma_interrupt_flag_get(DMA_CH0, DMA_INT_FLAG_FTF)) {
        dma_interrupt_flag_clear(DMA_CH0, DMA_INT_FLAG_FTF);
        spi_flash_dam_disable();
        if(audio_data.play_addr < audio_data.play_stop_addr){
            audio_data.play_addr += audio_data.size;
            #ifdef AUDIO_DEBUG
            for (int i = 0; i < audio_data.size / 2; i++) {
                if (i != 0 && i % 32 == 0) logd("\r\n");
                logd("%d,", buf[i]);
            }
            #endif
            audio_dma_config_init((uint16_t*)audio_data.buffer[audio_data.current_index_buf],audio_data.size/2);
            audio_data.current_index_buf = audio_data.current_index_buf ^ 1;
            spi_flash_dam_rx_tx_read_init(audio_data.buffer[audio_data.current_index_buf],audio_data.play_addr,audio_data.size,false);
        }else{

            #ifdef SUPPORT_AGING_TEST
			if(get_isaging_mode() == false){
                audio_deinit();
			}else{
                index = index == Audio_MAX ? index + 1 : Audio_Text;
                audio_play(index);
            }
			#else
            if(audio_factory.circulation == 1){
                audio_deinit();
                audio_play_fun(Audio_MAX - 1);
            }else{
                audio_deinit();
                #ifdef AUDIO_DEBUG
                if(index < Audio_MAX - 1){
                    index ++;
                }else{
                    index = 1;
                }
                audio_play(index);
                #endif
            }
            #endif
        }
    }
}
void DMA_Channel1_IRQHandler(void){

    if (dma_interrupt_flag_get(DMA_CH1, DMA_INT_FLAG_FTF)) {
        // 清除传输完成中断标志
        dma_interrupt_flag_clear(DMA_CH1, DMA_INT_FLAG_FTF);
        spi_flash_dam_disable();
        if(audio_data.play_addr < audio_data.play_stop_addr){
            audio_data.play_addr += audio_data.size;
            audio_dma_config_init((uint16_t*)audio_data.buffer[audio_data.current_index_buf],audio_data.size/2);
            audio_data.current_index_buf = audio_data.current_index_buf ^ 1;
            spi_flash_dam_rx_tx_read_init(audio_data.buffer[audio_data.current_index_buf],audio_data.play_addr,audio_data.size,false);
            audio_init();
        }
    }
}
void DMA_Channel2_IRQHandler(void){
    if (dma_interrupt_flag_get(DMA_CH2, DMA_INT_FLAG_FTF)) {
        // 清除传输完成中断标志
        dma_interrupt_flag_clear(DMA_CH2, DMA_INT_FLAG_FTF);
    }
}
void audio_play_fun(audio_list id)
{
    loge("start audio:%d\r\n",id);
    audio_data.play_addr = AUDIO_ADDR + tab[id].src_addr;
    audio_data.play_len = tab[id].len;
    audio_data.play_stop_addr = audio_data.play_addr + audio_data.play_len;
    logd("play_stop_addr:%d\r\n",audio_data.play_stop_addr);
    logd("addr:%d\r\n",AUDIO_ADDR);
    CurRun.audio_dma_run = true;
    spi_flash_dam_rx_tx_read_init((uint8_t *)audio_buffer,audio_data.play_addr,audio_data.size,true);
    ts_add_task(audio_play_task, T_2S, T_100MS, 0);
}
void audio_play(audio_list id)
{
    if(TS_CheckTaskIsRunning_by_func(audio_play_task) == false && CurRun.isnightmode == No_Night_Mode && TerUser.volume_switch == true
        && CurRun.LowPwr != Bat_Power_Low){
        audio_play_fun(id);
    }
}
void audio_start_wifi(void)
{
    audio_play(Audio_Start_wifi);
}
void audio_delay_play(void){
   ts_add_task(audio_start_wifi, T_4S, T_100MS, 1);
}
void audio_play_usb_disconnect_task(void)
{
    if(chg_d.charge_pin_detect() == false){
        audio_play(Audio_Usb_disconnect);
        TS_DelTask_by_func(audio_play_usb_disconnect_task);
    }
}
void audio_play_usb_disconnect(void)
{
    ts_add_task(audio_play_usb_disconnect_task, T_100MS, T_1S, 0);
}
#ifdef AUDIO_DEBUG
void audio_read(u8 id)
{
    audio_data.play_addr = AUDIO_ADDR + tab[id].src_addr;
    audio_data.play_len = tab[id].len;
    audio_data.play_stop_addr = audio_data.play_addr + audio_data.play_len;
    uint8_t pbuffer[64];
    while(audio_data.play_stop_addr > audio_data.play_addr){
        flash_d.flash_data_read(pbuffer,audio_data.play_addr,64);
        audio_data.play_addr += 64;
        logd("play addr:%d\r\n",audio_data.play_addr);
        for(int i = 0; i < 64 / 2; i++){
            loge("0x%04X, ", ((uint16_t *)pbuffer)[i]);
            if ((i + 1) % 8 == 0){
                loge("\r\n");
            }
        }
    }
}
#endif


bool audio_malloc_buffer(uint8_t** buffer)
{
    if (*buffer == NULL) {
        *buffer = (u8*)malloc(AUDIO_SECTOR_SIZE);
        if (*buffer == NULL) {
            return false;
        }
    }
    audio_factory.flash_addr = 0;
    audio_factory.audio_write_addr = 0;
    return true;
}

void spi_flash_audio_write_full(char* src_data)
{
    char* data = strstr(src_data, AUDIO_WRITE_DATA);
    if (data == NULL) {
        return;
    }

    if (audio_factory.p_flash_data == NULL) {
        if (!audio_malloc_buffer(&audio_factory.p_flash_data)) {  
            return;
        }
    }
    #ifdef AUDIO_DEBUG
    for(u8 i = 0; i < 64; i++)
        logd("%d,",src_data[i]); 
        logd("\r\n");
    #endif
    if ((uint32_t)audio_factory.audio_write_addr + WRITE_MAX_BYTE < AUDIO_SECTOR_SIZE) {  
        memcpy(audio_factory.p_flash_data + audio_factory.audio_write_addr, data + strlen(AUDIO_WRITE_DATA), WRITE_MAX_BYTE);
        audio_factory.audio_write_addr += WRITE_MAX_BYTE;
    } else {
        uint16_t remaining = AUDIO_SECTOR_SIZE - audio_factory.audio_write_addr;
        logd("remaining:%d\r\n",remaining);
        memcpy(audio_factory.p_flash_data + audio_factory.audio_write_addr, data + strlen(AUDIO_WRITE_DATA), remaining);
        spi_flash_audio_uint_write(audio_factory.flash_addr++, 1, audio_factory.p_flash_data);
        audio_factory.audio_write_addr = 0;
        memset(audio_factory.p_flash_data,0x00,AUDIO_SECTOR_SIZE);
        memcpy(audio_factory.p_flash_data + audio_factory.audio_write_addr, data + strlen(AUDIO_WRITE_DATA) + remaining, WRITE_MAX_BYTE - remaining);
        audio_factory.audio_write_addr = audio_factory.audio_write_addr + WRITE_MAX_BYTE - remaining;
        logd("audio_write_addr:%d\r\n",audio_factory.audio_write_addr);
    }
}

void spi_flash_audio_write_stop(char* src_data)
{
    char* data = strstr(src_data, AUDIO_WRITE_STOP);
    if (data == NULL) {
        return;
    }
    #ifdef AUDIO_DEBUG
    for(u8 i = 0; i < 64; i++)
        logd("%d,",src_data[i]); 
        logd("\r\n");
    #endif
    if (audio_factory.p_flash_data != NULL) {
        if(audio_factory.audio_write_addr > 0){
            spi_flash_audio_uint_write(audio_factory.flash_addr++, 1, audio_factory.p_flash_data);
        }
        free(audio_factory.p_flash_data);
    }
    audio_factory.p_flash_data = NULL;
    audio_factory.audio_write_addr = 0;
    audio_factory.flash_addr = 0;
}
void audio_factory_set_circulation(uint8_t value)
{
    audio_factory.circulation = value;
}
extern void usb_send_buf(u8 *data_buff, u8 data_len);
void audio_factory_fun(char * cmd_str)
{
    set_audio_factory_status(true);
    if(strstr(cmd_str,AUDIO_WRITE_DATA)){
        spi_flash_audio_write_full(cmd_str);
    }
    if(strstr(cmd_str,AUDIO_WRITE_STOP)){
        spi_flash_audio_write_stop(cmd_str);
        set_audio_factory_status(false);
    }
    usb_send_buf((uint8_t *)"OK", strlen("OK"));
}

bool get_audio_factory_status(void)
{
    return audio_factory_status;
}

void set_audio_factory_status(bool status)
{
    audio_factory_status = status;
}
#endif
