#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define MAX_TASK_QUEUE_SIZE 1000
#define MAX_WORKERS 5
#define BUFFER_SIZE 4096
#define WRITE_INTERVAL 500000 // 500ms
#define RETRY_TIMES 5
#define RETRY_DELAY 100 // 100ms
#define MAX_MEMORY_POOL_BLOCKS 100
#define MAX_RECONNECT_ATTEMPTS 5
#define RECONNECT_DELAY 1000000

typedef struct {
    char *buffer;
    size_t length;
} LogTask;

typedef struct {
    LogTask *tasks[MAX_TASK_QUEUE_SIZE];
    _Atomic size_t head;
    _Atomic size_t tail;
    volatile int running;
} TaskQueue;

typedef struct {
    TaskQueue *queue;
    FILE *output;
    struct {
        LogTask *blocks[MAX_MEMORY_POOL_BLOCKS];
        _Atomic size_t free_index;
    } memory_pool;
    pthread_t workers[MAX_WORKERS];
    volatile int worker_count;
    volatile int running;
} ThreadPool;

typedef struct {
    ThreadPool *pool;
    lua_State *L;
} Logger;

// 初始化内存池
void init_memory_pool(Logger *logger) {
    for (size_t i = 0; i < MAX_MEMORY_POOL_BLOCKS; ++i) {
        logger->pool->memory_pool.blocks[i] = malloc(sizeof(LogTask));
        logger->pool->memory_pool.blocks[i]->buffer = malloc(BUFFER_SIZE);
        logger->pool->memory_pool.blocks[i]->length = 0;
    }
    atomic_store(&logger->pool->memory_pool.free_index, 0);
}

// 从内存池中获取任务块
LogTask *get_task_from_pool(Logger *logger) {
    size_t index = atomic_fetch_add(&logger->pool->memory_pool.free_index, 1);
    if (index < MAX_MEMORY_POOL_BLOCKS) {
        LogTask *task = logger->pool->memory_pool.blocks[index];
        task->length = 0;
        return task;
    }
    return NULL; // 内存池已满
}

// 归还任务块到内存池
void return_task_to_pool(Logger *logger, LogTask *task) {
    for (size_t i = 0; i < MAX_MEMORY_POOL_BLOCKS; ++i) {
        if (logger->pool->memory_pool.blocks[i] == task) {
            atomic_fetch_sub(&logger->pool->memory_pool.free_index, 1);
            logger->pool->memory_pool.blocks[i]->length = 0;
            break;
        }
    }
}

// 检测标准输出是否可用
bool is_stdout_available() {
    return (fflush(stdout) == 0);
}

// 尝试重新连接标准输出
bool reconnect_stdout() {
    fclose(stdout);
    stdout = fopen("/dev/stdout", "w");
    if (stdout == NULL) {
        return false;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    return true;
}

// 工作者线程函数
void *worker(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    TaskQueue *queue = pool->queue;

    while (pool->running) {
        LogTask *task = NULL;
        size_t head = atomic_load(&queue->head);
        size_t tail = atomic_load(&queue->tail);

        if (head != tail) {
            task = queue->tasks[head];
            atomic_store(&queue->head, (head + 1) % MAX_TASK_QUEUE_SIZE);
        }

        if (task != NULL) {
            if (!is_stdout_available()) {
                int reconnect_attempts = 0;
                while (reconnect_attempts < MAX_RECONNECT_ATTEMPTS && !is_stdout_available()) {
                    if (reconnect_stdout()) {
                        break;
                    }
                    reconnect_attempts++;
                    usleep(RECONNECT_DELAY);
                }
                if (!is_stdout_available()) {
                    fprintf(stderr, "Failed to reconnect stdout after %d attempts. Dropping log message.\n", MAX_RECONNECT_ATTEMPTS);
                    return_task_to_pool((Logger *)pool->arg, task);
                    continue;
                }
            }

            int retry_count = 0;
            bool success = false;
            while (retry_count < RETRY_TIMES && !success) {
                if (fwrite(task->buffer, 1, task->length, stdout) == task->length) {
                    success = true;
                } else {
                    retry_count++;
                    usleep(RETRY_DELAY * 1000);
                }
            }

            if (!success) {
                fprintf(stderr ",Failed to write log after %d retries\n", RETRY_TIMES);
            }

            return_task_to_pool((Logger *)pool->arg, task);
        } else {
            usleep(1000); // 空闲时休眠
        }
    }

    return NULL;
}

// 初始化线程池
ThreadPool *create_thread_pool(int max_workers, Logger *logger) {
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    if (pool == NULL) {
        return NULL;
    }

    pool->running = 1;
    pool->worker_count = 0;
    pool->arg = logger;

    // 初始化任务队列
    TaskQueue *queue = malloc(sizeof(TaskQueue));
    if (queue == NULL) {
        free(pool);
        return NULL;
    }
    atomic_init(&queue->head, 0);
    atomic_init(&queue->tail, 0);
    queue->running = 1;
    pool->queue = queue;

    // 创建工作者线程
    for (int i = 0; i < max_workers; ++i) {
        if (pthread_create(&pool->workers[i], NULL, worker, pool)) {
            fprintf(stderr, "Failed to create worker thread\n");
            break;
        }
        pool->worker_count++;
    }

    return pool;
}

// 初始化日志记录器
Logger *logger_init(lua_State *L) {
    Logger *logger = malloc(sizeof(Logger));
    if (logger == NULL) {
        return NULL;
    }

    logger->L = L;

    // 创建线程池
    logger->pool = create_thread_pool(MAX_WORKERS, logger);
    if (logger->pool == NULL) {
        free(logger);
        return NULL;
    }

    logger->pool->output = stdout;

    // 初始化内存池
    init_memory_pool(logger);

    return logger;
}

// 记录日志消息
void log_record(Logger *logger, const char *message, size_t length) {
    LogTask *task = get_task_from_pool(logger);
    if (task == NULL) {
        return; // 内存池已满，暂时无法记录日志
    }

    if (length > BUFFER_SIZE) {
        length = BUFFER_SIZE;
    }
    memcpy(task->buffer, message, length);
    task->length = length;

    // 将任务添加到任务队列
    size_t tail = atomic_load(&logger->pool->queue->tail);
    size_t next_tail = (tail + 1) % MAX_TASK_QUEUE_SIZE;

    if (next_tail == atomic_load(&logger->pool->queue->head)) {
        // 队列已满，归还内存块
        return_task_to_pool(logger, task);
        return;
    }

    logger->pool->queue->tasks[tail] = task;
    atomic_store(&logger->pool->queue->tail, next_tail);
}

// 销毁日志记录器
void logger_destroy(Logger *logger) {
    if (logger == NULL || logger->pool == NULL) {
        return;
    }

    // 停止线程池
    logger->pool->running = 0;

    // 等待所有工作者线程退出
    for (int i = 0; i < MAX_WORKERS; ++i) {
        if (pthread_join(logger->pool->workers[i], NULL)) {
            fprintf(stderr, "Failed to join worker thread\n");
        }
    }

    // 清理内存池
    for (size_t i = 0; i < MAX_MEMORY_POOL_BLOCKS; ++i) {
        free(logger->pool->memory_pool.blocks[i]->buffer);
        free(logger->pool->memory_pool.blocks[i]);
    }

    // 清理任务队列
    free(logger->pool->queue);
    free(logger->pool);

    free(logger);
}

// Lua绑定函数：记录日志消息
static int lua_log_record(lua_State *L) {
    const char *message = luaL_checkstring(L, 1);
    Logger *logger = luaL_checkudata(L, 2, "Logger");

    log_record(logger, message, strlen(message));

    return 0;
}

// Lua绑定函数：销毁日志记录器
static int lua_logger_destroy(lua_State *L) {
    Logger *logger = luaL_checkudata(L, 1, "Logger");
    logger_destroy(logger);
    return 0;
}

// Lua元方法：垃圾回收
static int lua_logger_gc(lua_State *L) {
    Logger *logger = luaL_checkudata(L, 1, "Logger");
    logger_destroy(logger);
    return 0;
}

// Lua模块初始化
int luaopen_logger(lua_State *L) {
    luaL_newmetatable(L, "Logger");

    static const luaL_Reg methods[] = {
        {"__gc", lua_logger_gc},
        {NULL, NULL}
    };

    luaL_setfuncs(L, methods, 0);

    static const luaL_Reg functions[] = {
        {"record", lua_log_record},
        {"destroy", lua_logger_destroy},
        {NULL, NULL}
    };

    luaL_setfuncs(L, functions, 0);

    static const luaL_Reg create_functions[] = {
        {"new", [](lua_State *L) -> int {
            Logger *logger = logger_init(L);
            if (!logger) {
                lua_pushnil(L);
                lua_pushstring(L, "Failed to initialize logger");
                return 2;
            }

            luaL_newmetatable(L, "Logger");
            lua_pushlightuserdata(L, logger);
            lua_setfield(L, -2, "__ptr");
            lua_setmetatable(L, -2);

            return 1;
        }},
        {NULL, NULL}
    };

    luaL_setfuncs(L, create_functions, 0);

    return 1;
}