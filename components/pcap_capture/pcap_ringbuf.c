/* PCAP Ring Buffer - Thread-safe circular buffer for packet capture

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "lwip/pbuf.h"

// Internal header for ring buffer
#include "pcap_ringbuf.h"

static const char *TAG = "pcap_ringbuf";

// Ring buffer state
static uint8_t *ringbuf_data = NULL;
static size_t ringbuf_size = 0;
static size_t ringbuf_head = 0;      // Write position
static size_t ringbuf_tail = 0;      // Read position
static size_t ringbuf_available = 0; // Bytes available to read
static uint32_t dropped_packets = 0;
static SemaphoreHandle_t ringbuf_mutex = NULL;
static SemaphoreHandle_t data_ready_sem = NULL;

bool ringbuf_init(void)
{
    if (ringbuf_mutex != NULL) {
        ESP_LOGW(TAG, "Ring buffer already initialized");
        return true;
    }

    ringbuf_mutex = xSemaphoreCreateMutex();
    if (ringbuf_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return false;
    }

    data_ready_sem = xSemaphoreCreateBinary();
    if (data_ready_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create semaphore");
        vSemaphoreDelete(ringbuf_mutex);
        ringbuf_mutex = NULL;
        return false;
    }

    ESP_LOGI(TAG, "Ring buffer initialized");
    return true;
}

bool ringbuf_alloc(size_t size)
{
    if (ringbuf_mutex == NULL) {
        ESP_LOGE(TAG, "Ring buffer not initialized");
        return false;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (ringbuf_data != NULL) {
        ESP_LOGW(TAG, "Ring buffer already allocated");
        xSemaphoreGive(ringbuf_mutex);
        return true;
    }

    ringbuf_data = malloc(size);
    if (ringbuf_data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate ring buffer (%d bytes)", size);
        xSemaphoreGive(ringbuf_mutex);
        return false;
    }

    ringbuf_size = size;
    ringbuf_head = 0;
    ringbuf_tail = 0;
    ringbuf_available = 0;
    dropped_packets = 0;

    xSemaphoreGive(ringbuf_mutex);

    // Drain any stale semaphore signal
    xSemaphoreTake(data_ready_sem, 0);

    ESP_LOGI(TAG, "Ring buffer allocated (%d bytes)", size);
    return true;
}

/* Releases the data buffer only.  The mutex and semaphore are created once by
 * ringbuf_init() and must outlive it: this runs on every client disconnect
 * while the packet hook may still be inside ringbuf_write_record(), and ringbuf_init()
 * is not called again for the lifetime of the server task. */
void ringbuf_free(void)
{
    if (ringbuf_mutex == NULL) {
        return;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (ringbuf_data != NULL) {
        free(ringbuf_data);
        ringbuf_data = NULL;
        ringbuf_size = 0;
        ringbuf_head = 0;
        ringbuf_tail = 0;
        ringbuf_available = 0;
        dropped_packets = 0;
        ESP_LOGI(TAG, "Ring buffer freed");
    }

    xSemaphoreGive(ringbuf_mutex);
}

void ringbuf_reset(void)
{
    if (ringbuf_mutex == NULL) {
        return;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    ringbuf_head = 0;
    ringbuf_tail = 0;
    ringbuf_available = 0;
    dropped_packets = 0;
    xSemaphoreGive(ringbuf_mutex);
}

// Copy len bytes to the head, wrapping around. Caller holds the mutex and has
// checked the free space.
static void put_locked(const uint8_t *src, size_t len)
{
    size_t first_chunk = ringbuf_size - ringbuf_head;
    if (first_chunk >= len) {
        memcpy(ringbuf_data + ringbuf_head, src, len);
        ringbuf_head = (ringbuf_head + len) % ringbuf_size;
    } else {
        memcpy(ringbuf_data + ringbuf_head, src, first_chunk);
        memcpy(ringbuf_data, src + first_chunk, len - first_chunk);
        ringbuf_head = len - first_chunk;
    }
    ringbuf_available += len;
}

bool ringbuf_write_record(const uint8_t *hdr, size_t hdr_len,
                          const uint8_t *prefix, size_t prefix_len,
                          const struct pbuf *p, size_t p_len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return false;
    }

    // Non-blocking take for ISR/hook context
    if (xSemaphoreTake(ringbuf_mutex, 0) != pdTRUE) {
        dropped_packets++;
        return false;
    }

    // Re-check after taking mutex (buffer may have been freed)
    if (ringbuf_data == NULL) {
        xSemaphoreGive(ringbuf_mutex);
        return false;
    }

    size_t len = hdr_len + prefix_len + p_len;
    if (len > ringbuf_size - ringbuf_available) {
        dropped_packets++;
        xSemaphoreGive(ringbuf_mutex);
        return false;
    }

    put_locked(hdr, hdr_len);
    if (prefix_len > 0) {
        put_locked(prefix, prefix_len);
    }
    for (const struct pbuf *q = p; q != NULL && p_len > 0; q = q->next) {
        size_t n = (q->len < p_len) ? q->len : p_len;
        put_locked((const uint8_t *)q->payload, n);
        p_len -= n;
    }

    xSemaphoreGive(ringbuf_mutex);

    // Signal data ready
    xSemaphoreGive(data_ready_sem);
    return true;
}

size_t ringbuf_read(uint8_t *data, size_t max_len, TickType_t timeout)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return 0;
    }

    // Wait for data to be available
    if (xSemaphoreTake(data_ready_sem, timeout) != pdTRUE) {
        return 0; // Timeout
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    // Check if buffer was freed while we waited
    if (ringbuf_data == NULL || ringbuf_available == 0) {
        xSemaphoreGive(ringbuf_mutex);
        return 0;
    }

    size_t to_read = (max_len < ringbuf_available) ? max_len : ringbuf_available;

    // Read data, handling wrap-around
    size_t first_chunk = ringbuf_size - ringbuf_tail;
    if (first_chunk >= to_read) {
        // No wrap needed
        memcpy(data, ringbuf_data + ringbuf_tail, to_read);
        ringbuf_tail = (ringbuf_tail + to_read) % ringbuf_size;
    } else {
        // Wrap around
        memcpy(data, ringbuf_data + ringbuf_tail, first_chunk);
        memcpy(data + first_chunk, ringbuf_data, to_read - first_chunk);
        ringbuf_tail = to_read - first_chunk;
    }

    ringbuf_available -= to_read;

    // If more data available, signal again
    if (ringbuf_available > 0) {
        xSemaphoreGive(data_ready_sem);
    }

    xSemaphoreGive(ringbuf_mutex);

    return to_read;
}

size_t ringbuf_peek(uint8_t *data, size_t max_len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (ringbuf_available == 0) {
        xSemaphoreGive(ringbuf_mutex);
        return 0;
    }

    size_t to_read = (max_len < ringbuf_available) ? max_len : ringbuf_available;

    // Read data without moving tail, handling wrap-around
    size_t first_chunk = ringbuf_size - ringbuf_tail;
    if (first_chunk >= to_read) {
        memcpy(data, ringbuf_data + ringbuf_tail, to_read);
    } else {
        memcpy(data, ringbuf_data + ringbuf_tail, first_chunk);
        memcpy(data + first_chunk, ringbuf_data, to_read - first_chunk);
    }

    xSemaphoreGive(ringbuf_mutex);

    return to_read;
}

void ringbuf_skip(size_t len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (len > ringbuf_available) {
        len = ringbuf_available;
    }

    ringbuf_tail = (ringbuf_tail + len) % ringbuf_size;
    ringbuf_available -= len;

    xSemaphoreGive(ringbuf_mutex);
}

size_t ringbuf_available_bytes(void)
{
    if (ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    size_t avail = ringbuf_available;
    xSemaphoreGive(ringbuf_mutex);

    return avail;
}

size_t ringbuf_free_space(void)
{
    if (ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    size_t free_space = ringbuf_size - ringbuf_available;
    xSemaphoreGive(ringbuf_mutex);

    return free_space;
}

size_t ringbuf_total_size(void)
{
    return ringbuf_size;
}

uint32_t ringbuf_get_dropped_count(void)
{
    return dropped_packets;
}

void ringbuf_reset_dropped_count(void)
{
    dropped_packets = 0;
}
