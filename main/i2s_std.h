#ifndef i2s__h
#define i2s__h
#include <stdint.h>
#include <stdlib.h>

#define CHANNELS (2)
#define BITSPERSAMPLE (32)
#define SAMPLE_SIZE (240)
#define BUFF_SIZE (SAMPLE_SIZE * CHANNELS * (BITSPERSAMPLE / 8)) // 两声道，32比特
#define AUDIO_QUEUE_SIZE 10
// Structure to hold audio data
typedef struct
{
    uint8_t samples[BUFF_SIZE];
    size_t size;
} audio_data_t;

#endif