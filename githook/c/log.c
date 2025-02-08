#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define MAX_LOG_QUEUE_SIZE 1000
#define BUFFER_SIZE 4096
#define WRITE_INTERVAL 500000 // 500ms
#define RETRY_TIMES 5
#define RETRY_DELAY 100 // 100ms

// 内存池结构
typedef struct {
    char **blocks;
    int block_size;
    int current_block;
    int block_count;
} MemoryPool;

MemoryPool *init_memory_pool(int block_size, int block_count) {
    MemoryPool *pool = (MemoryPool *)malloc(sizeof(MemoryPool));
    if (!pool) {
        fprintf(stderr, "Failed to allocate memory for memory pool\n");
        return NULL;
    }
    pool->block_size = block_size;
    pool->current_block = 0;
    pool->block_count = block_count;

    pool->blocks = (char **)malloc(block_count * sizeof(char *));
    if (!pool->blocks) {
        fprintf(stderr, "Failed to allocate memory for memory pool blocks\n");
        free(pool);
        return NULL;
    }

    for (int i = 0; i < block_count; ++i) {
        pool->blocks[i] = (char *)malloc(block_size);
        if (!pool->blocks[i]) {
            fprintf(stderr, "Failed to allocate memory for memory pool block %d\n", i);
            // 释放已分配的内存块
            for (int j = 0; j < i; ++j) {
                free(pool->blocks[j]);
            }
            free(pool->blocks);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

char *allocate_memory(MemoryPool *pool) {
    if (pool->current_block >= pool->block_count) {
        return NULL; // 所有块已被分配
    }

    char *block = pool->blocks[pool->current_block];
    pool->current_block++;

    return block;
}

// 无锁环形队列结构
typedef struct {
    char **messages;
    int head;
    int tail;
    int count;
    pthread_spinlock_t lock;
} LockFreeLogQueue;

LockFreeLogQueue *init_lock_free_log_queue() {
    LockFreeLogQueue *queue = (LockFreeLogQueue *)malloc(sizeof(LockFreeLogQueue));
    if (!queue) {
        fprintf(stderr, "Failed to allocate memory for log queue\n");
        return NULL;
    }

    queue->messages = (char **)calloc(MAX_LOG_QUEUE_SIZE, sizeof(char *));
    if (!queue->messages) {
        fprintf(stderr, "Failed to allocate memory for log queue messages\n");
        free(queue);
        return NULL;
    }

    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;

    if (pthread_spin_init(&queue->lock, PTHREAD_SPINLOCK_INITIALIZER)) {
        fprintf(stderr, "Failed to initialize spin lock\n");
        free(queue->messages);
        free(queue);
        return NULL;
    }

    return queue;
}

void add_log_message(LockFreeLogQueue *queue, const char *message) {
    assert(queue != NULL && "log_queue must be initialized before use");

    pthread_spin_lock(&queue->lock);

    while (queue->count >= MAX_LOG_QUEUE_SIZE) {
        pthread_spin_unlock(&queue->lock);
        usleep(100); // 稍微等待一下
        pthread_spin_lock(&queue->lock);
    }

    char *new_message = allocate_memory(memory_pool); // 使用内存池分配内存
    if (new_message == NULL) {
        // 内存不足，可以考虑其他处理方式
        pthread_spin_unlock(&queue->lock);
        return;
    }

    strcpy(new_message, message);
    queue->messages[queue->head] = new_message;
    queue->head = (queue->head + 1) % MAX_LOG_QUEUE_SIZE;
    queue->count++;

    pthread_spin_unlock(&queue->lock);
}

// 线程池结构
typedef struct {
    LockFreeLogQueue *queue;
    pthread_t *threads;
    int thread_count;
} ThreadPool;

ThreadPool *create_thread_pool(LockFreeLogQueue *queue, int thread_count) {
    ThreadPool *pool = (ThreadPool *)malloc(sizeof(ThreadPool));
    if (!pool) {
        fprintf(stderr, "Failed to allocate memory for thread pool\n");
        return NULL;
    }

    pool->queue = queue;
    pool->thread_count = thread_count;

    pool->threads = (pthread_t *)malloc(thread_count * sizeof(pthread_t));
    if (!pool->threads) {
        fprintf(stderr, "Failed to allocate memory for thread pool threads\n");
        free(pool);
        return NULL;
    }

    for (int i = 0; i < thread_count; ++i) {
        if (pthread_create(&pool->threads[i], NULL, log_consumer, pool)) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            // 释放已创建的线程
            for (int j = 0; j < i; ++j) {
                pthread_cancel(pool->threads[j]);
                pthread_join(pool->threads[j], NULL);
            }
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

// 后台线程函数（批量写入）
void *log_consumer(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    LockFreeLogQueue *queue = pool->queue;

    FILE *stdout = fopen("/dev/stdout", "w");

    if (stdout == NULL) {
        // 重试打开标准输出
        for (int i = 0; i < RETRY_TIMES; ++i) {
            stdout = fopen("/dev/stdout", "w");
            if (stdout != NULL) break;
            usleep(RETRY_DELAY * 1000);
        }

        if (stdout == NULL) {
            // 记录错误日志并退出
            perror("Failed to open stdout after retries");
            return NULL;
        }
    }

    char *buffer = (char *)malloc(BUFFER_SIZE);
    size_t buffer_pos = 0;

    struct timeval last_write_time;

    while (1) {
        pthread_spin_lock(&queue->lock);

        if (queue->count > 0) {
            char *message = queue->messages[queue->tail];
            size_t msg_len = strlen(message) + 1; // 包括换行符

            if (buffer_pos + msg_len <= BUFFER_SIZE) {
                strcpy(buffer + buffer_pos, message);
                buffer_pos += msg_len;

                queue->tail = (queue->tail + 1) % MAX_LOG_QUEUE_SIZE;
                queue->count--;

                free(message); // 释放内存块
            } else {
                // 写入缓冲区到标准输出
                fwrite(buffer, 1, buffer_pos, stdout);
                fflush(stdout);
                buffer_pos = 0;
            }
        }

        pthread_spin_unlock(&queue->lock);

        // 定期写入剩余内容
        gettimeofday(&current_time, NULL);
        if ((current_time.tv_sec - last_write_time.tv_sec) > 0 ||
            (current_time.tv_usec - last_write_time.tv_usec) > WRITE_INTERVAL) {
            if (buffer_pos > 0) {
                fwrite(buffer, 1, buffer_pos, stdout);
                fflush(stdout);
                buffer_pos = 0;
                last_write_time = current_time;
            }
        }

        // 模拟其他任务或短暂休眠
        usleep(1000); // 1ms
    }

    free(buffer);
    fclose(stdout);
    return NULL;
}

// 注册全局变量
void register_globals(lua_State *L, MemoryPool *memory_pool, LockFreeLogQueue *log_queue, ThreadPool *thread_pool) {
    // 将内存池注册为全局变量
    lua_pushlightuserdata(L, memory_pool);
    luaglobal_set(L, "memory_pool");

    // 将无锁环形队列注册为全局变量
    lua_pushlightuserdata(L, log_queue);
    lua_setglobal(L, "log_queue");

    // 将线程池注册为全局变量
    lua_pushlightuserdata(L, thread_pool);
    lua_setglobal(L, "thread_pool");
}

// Lua绑定函数
static int lua_init_memory_pool(lua_State *L) {
    int block_size = luaL_checkinteger(L, 1);
    int block_count = luaL_checkinteger(L, 2);

    MemoryPool *pool = init_memory_pool(block_size, block_count);
    if (!pool) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlightuserdata(L, pool);
    return 1;
}

static int lua_init_lock_free_log_queue(lua_State *L) {
    LockFreeLogQueue *queue = init_lock_free_log_queue();
    if (!queue) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlightuserdata(L, queue);
    return 1;
}

static int lua_create_thread_pool(lua_State *L) {
    LockFreeLogQueue *queue = (LockFreeLogQueue *)luaL_checkudata(L, 1, "LockFreeLogQueue");
    int thread_count = luaL_checkinteger(L, 2);

    ThreadPool *pool = create_thread_pool(queue, thread_count);
    if (!pool) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlightuserdata(L, pool);
    return 1;
}

static int lua_add_log_message(lua_State *L) {
    const char *message = luaL_checkstring(L, 1);
    LockFreeLogQueue *queue = (LockFreeLogQueue *)lua_getglobal(L, "log_queue");

    if (!queue) {
        luaL_error(L, "log_queue not initialized");
        return 0;
    }

    add_log_message(queue, message);

    return 0;
}

static int lua_register_globals(lua_State *L) {
    MemoryPool *memory_pool = (MemoryPool *)luaL_checkudata(L, 1, "MemoryPool");
    LockFreeLogQueue *log_queue = (LockFreeLogQueue *)luaL_checkudata(L, 2, "LockFreeLogQueue");
    ThreadPool *thread_pool = (ThreadPool *)luaL_checkudata(L, 3, "ThreadPool");

    register_globals(L, memory_pool, log_queue, thread_pool);

    return 0;
}

void register_lua_functions(lua_State *L) {
    static const luaL_Reg functions[] = {
        {"init_memory_pool", lua_init_memory_pool},
        {"init_lock_free_log_queue", lua_init_lock_free_log_queue},
        {"create_thread_pool", lua_create_thread_pool},
        {"add_log_message", lua_add_log_message},
        {"register_globals", lua_register_globals},
        {NULL, NULL}
    };

    luaL_setfuncs(L, functions, 0);
}

int main() {
    // 初始化Lua环境
    lua_State *l = luaL_newstate();
    luaL_openlibs(l);

    register_lua_functions(l);

    // 加载并执行Lua脚本
    const char *script =
        "local log_module = require('add_log_message')\n"
        "local memory_pool = log_module.init_memory_pool(1024, 100)\n"
        "local log_queue = log_module.init_lock_free_log_queue()\n"
        "local thread_pool = log_module.create_thread_pool(log_queue, 4)\n"
        "\n"
        "log_module.register_globals(memory_pool, log_queue, thread_pool)\n"
        "\n"
        "-- 示例：添加日志消息\n"
        "for i=1,10 do\n"
        "   log_module.add_log_message(string.format('Log message %d', i))\n"
        "end";

    if (luaL_dostring(l, script)) {
        fprintf(stderr, "Error: %s\n", lua_tostring(l, -1));
        lua_pop(l, 1);
    }

    // 等待后台线程处理完所有消息
    while (log_queue->count > 0) {
        usleep(100000); // 等待100毫秒
    }

    // 清理资源
    destroy_thread_pool(thread_pool);
    destroy_log_queue(log_queue);
    cleanup(memory_pool, l);

    return 0;
}