#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

typedef struct {
    void** data;     // 存储元素的指针数组
    size_t head;     // 队列头部索引
    size_t tail;     // 队列尾部索引
    size_t size;     // 队列容量
    pthread_mutex_t lock; // 互斥锁，用于线程同步
} lua_queue_t;

// 初始化队列
lua_queue_t* lua_queue_new(size_t initial_size) {
    lua_queue_t* queue = (lua_queue_t*)malloc(sizeof(lua_queue_t));
    if (!queue) {
        return NULL;
    }
    queue->data = (void**)calloc(initial_size, sizeof(void*));
    if (!queue->data) {
        free(queue);
        return NULL;
    }
    queue->head = 0;
    queue->tail = 0;
    queue->size = initial_size;
    pthread_mutex_init(&queue->lock, NULL);
    return queue;
}

// 销毁队列
void lua_queue_destroy(lua_queue_t* queue) {
    if (queue) {
        free(queue->data);
        pthread_mutex_destroy(&queue->lock);
        free(queue);
    }
}

// 入队操作
int lua_queue_enqueue(lua_queue_t* queue, void* value) {
    if (!queue) {
        return -1;
    }
    pthread_mutex_lock(&queue->lock);
    // 检查队列是否已满
    if ((queue->tail + 1) % queue->size == queue->head) {
        pthread_mutex_unlock(&queue->lock);
        return -1; // 队列已满
    }
    queue->data[queue->tail] = value;
    queue->tail = (queue->tail + 1) % queue->size;
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

// 出队操作
void* lua_queue_dequeue(lua_queue_t* queue) {
    if (!queue) {
        return NULL;
    }
    pthread_mutex_lock(&queue->lock);
    // 检查队列是否为空
    if (queue->head == queue->tail) {
        pthread_mutex_unlock(&queue->lock);
        return NULL; // 队列为空
    }
    void* value = queue->data[queue->head];
    queue->head = (queue->head + 1) % queue->size;
    pthread_mutex_unlock(&queue->lock);
    return value;
}

// 查看队首元素
void* lua_queue_peek(lua_queue_t* queue) {
    if (!queue || queue->head == queue->tail) {
        return NULL; // 队列为空
    }
    pthread_mutex_lock(&queue->lock);
    void* value = queue->data[queue->head];
    pthread_mutex_unlock(&queue->lock);
    return value;
}

// 获取队列长度
size_t lua_queue_length(lua_queue_t* queue) {
    if (!queue) {
        return 0;
    }
    pthread_mutex_lock(&queue->lock);
    size_t length = (queue->tail >= queue->head) ?
                    (queue->tail - queue->head) :
                    (queue->size - (queue->head - queue->tail));
    pthread_mutex_unlock(&queue->lock);
    return length;
}