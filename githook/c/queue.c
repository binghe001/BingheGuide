#include <stdlib.h>
#include <pthread.h>

typedef struct {
    void** data;
    size_t head;
    size_t tail;
    size_t size;
    pthread_mutex_t lock;
} lua_queue_t;

// 初始化队列
lua_queue_t* lua_queue_new(size_t initial_size) {
    lua_queue_t* queue = (lua_queue_t*)malloc(sizeof(lua_queue_t));
    queue->data = (void**)calloc(initial_size, sizeof(void*));
    queue->head = 0;
    queue->tail = 0;
    queue->size = initial_size;
    pthread_mutex_init(&queue->lock, NULL);
    return queue;
}

// 销毁队列
void lua_queue_destroy(lua_queue_t* queue) {
    free(queue->data);
    free(queue);
}

// 入队操作
int lua_queue_enqueue(lua_queue_t* queue, void* value) {
    pthread_mutex_lock(&queue->lock);
    if ((queue->tail + 1) % queue->size == queue->head) {
        pthread_mutex_unlock(&queue->lock);
        return -1;  // 队列已满
    }
    queue->data[queue->tail] = value;
    queue->tail = (queue->tail + 1) % queue->size;
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

// 出队操作
void* lua_queue_dequeue(lua_queue_t* queue) {
    pthread_mutex_lock(&queue->lock);
    if (queue->head == queue->tail) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;  // 队列为空
    }
    void* value = queue->data[queue->head];
    queue->data[queue->head] = NULL;
    queue->head = (queue->head + 1) % queue->size;
    pthread_mutex_unlock(&queue->lock);
    return value;
}

// 查看队首元素
void* lua_queue_peek(lua_queue_t* queue) {
    pthread_mutex_lock(&queue->lock);
    if (queue->head == queue->tail) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }
    void* value = queue->data[queue->head];
    pthread_mutex_unlock(&queue->lock);
    return value;
}

// 获取队列长度
size_t lua_queue_length(lua_queue_t* queue) {
    pthread_mutex_lock(&queue->lock);
    size_t length = (queue->tail - queue->head) % queue->size;
    pthread_mutex_unlock(&queue->lock);
    return length;
}