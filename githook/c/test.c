#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <lua.h>
#include <lauxlib.h>
#include <stdatomic.h>

// 定义日志任务结构体
typedef struct LogTask {
    char *message;
    size_t length;
    struct LogTask *next;
} LogTask;

// 定义任务队列结构体
typedef struct TaskQueue {
    LogTask **tasks;
    size_t head;
    size_t tail;
    size_t capacity;
    volatile int running;
} TaskQueue;

// 定义日志记录器配置结构体
typedef struct LoggerConfig {
    int max_task_queue_size;
    int max_workers;
    int buffer_size;
    int write_interval;
    int retry_times;
    int retry_delay;
    int max_memory_pool_blocks;
    int max_reconnect_attempts;
    int reconnect_delay;
} LoggerConfig;

// 定义线程池结构体
typedef struct ThreadPool {
    TaskQueue *queue;
    FILE *output;
    struct MemoryPool {
        LogTask **blocks;
        _Atomic size_t free_index;
    } memory_pool;
    pthread_t *workers;
    volatile int worker_count;
    volatile int running;
    LoggerConfig *config;
} ThreadPool;

// 定义日志记录器结构体
typedef struct Logger {
    lua_State *L;
    ThreadPool *pool;
} Logger;

// 静态标志，用于确保luaopen_logger只被初始化一次
static bool initialized = false;

// 从Lua获取配置参数
static bool get_config_from_lua(lua_State *L, LoggerConfig *config) {
    if (lua_istable(L, -1)) {
        // 获取max_task_queue_size
        lua_getfield(L, -1, "max_task_queue_size");
        if (!lua_isinteger(L, -1)) {
            config->max_task_queue_size = 1000; // 默认值
            lua_pop(L, 1);
        } else {
            config->max_task_queue_size = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取max_workers
        lua_getfield(L, -1, "max_workers");
        if (!lua_isinteger(L, -1)) {
            config->max_workers = 5; // 默认值
            lua_pop(L, 1);
        } else {
            config->max_workers = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取buffer_size
        lua_getfield(L, -1, "buffer_size");
        if (!lua_isinteger(L, -1)) {
            config->buffer_size = 4096; // 默认值
            lua_pop(L, 1);
        } else {
            config->buffer_size = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取write_interval
        lua_getfield(L, -1, "write_interval");
        if (!lua_isinteger(L, -1)) {
            config->write_interval = 500000; // 默认值
            lua_pop(L, 1);
        } else {
            config->write_interval = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取retry_times
        lua_getfield(L, -1, "retry_times");
        if (!lua_isinteger(L, -1)) {
            config->retry_times = 5; // 默认值
            lua_pop(L, 1);
        } else {
            config->retry_times = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取retry_delay
        lua_getfield(L, -1, "retry_delay");
        if (!lua_isinteger(L, -1)) {
            config->retry_delay = 100; // 默认值
            lua_pop(L, 1);
        } else {
            config->retry_delay = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取max_memory_pool_blocks
        lua_getfield(L, -1, "max_memory_pool_blocks");
        if (!lua_isinteger(L, -1)) {
            config->max_memory_pool_blocks = 100; // 默认值
            lua_pop(L, 1);
        } else {
            config->max_memory_pool_blocks = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取max_reconnect_attempts
        lua_getfield(L, -1, "max_reconnect_attempts");
        if (!lua_isinteger(L, -1)) {
            config->max_reconnect_attempts = 5; // 默认值
            lua_pop(L, 1);
        } else {
            config->max_reconnect_attempts = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        // 获取reconnect_delay
        lua_getfield(L, -1, "reconnect_delay");
        if (!lua_isinteger(L, -1)) {
            config->reconnect_delay = 1000000; // 默认值
            lua_pop(L, 1);
        } else {
            config->reconnect_delay = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        return true;
    }
    return false;
}

// 初始化内存池
static void init_memory_pool(Logger *logger) {
    ThreadPool *pool = logger->pool;
    pool->memory_pool.blocks = malloc(pool->config->max_memory_pool_blocks * sizeof(LogTask *));
    if (pool->memory_pool.blocks == NULL) {
        fprintf(stderr, "Failed to allocate memory pool\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < pool->config->max_memory_pool_blocks; ++i) {
        pool->memory_pool.blocks[i] = malloc(pool->config->buffer_size);
    }
    atomic_init(&pool->memory_pool.free_index, 0);
}

// 工作者线程函数
static void *worker(void *arg) {
    ThreadPool *pool = arg;
    while (pool->running) {
        LogTask *task = NULL;

        // 尝试从任务队列中取出任务
        size_t head = atomic_load(&pool->queue->head);
        if (head != atomic_load(&pool->queue->tail)) {
            task = pool->queue->tasks[head];
            atomic_store(&pool->queue->head, (head + 1) % pool->queue->capacity);
        }

        if (task) {
            // 处理日志任务
            fwrite(task->message, sizeof(char), task->length, pool->output);

            // 将任务归还内存池
            size_t free_index = atomic_fetch_add(&pool->memory_pool.free_index, 1) % pool->config->max_memory_pool_blocks;
            pool->memory_pool.blocks[free_index] = task;
        }

        // 等待下一个间隔
        usleep(pool->config->write_interval);
    }

    return NULL;
}

// 创建任务队列
static TaskQueue *create_task_queue(int capacity) {
    TaskQueue *queue = malloc(sizeof(TaskQueue));
    if (queue == NULL) {
        return NULL;
    }

    queue->tasks = malloc(capacity * sizeof(LogTask *));
    if (queue->tasks == NULL) {
        free(queue);
        return NULL;
    }

    atomic_init(&queue->head, 0);
    atomic_init(&queue->tail, 0);
    queue->capacity = capacity;
    queue->running = 1;

    return queue;
}

// 创建线程池
static ThreadPool *create_thread_pool(LoggerConfig *config) {
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    if (pool == NULL) {
        return NULL;
    }

    pool->running = 1;
    pool->worker_count = 0;
    pool->config = config;

    // 创建任务队列
    pool->queue = create_task_queue(config->max_task_queue_size);
    if (pool->queue == NULL) {
        free(pool);
        return NULL;
    }

    // 分配工作者线程数组
    pool->workers = malloc(config->max_workers * sizeof(pthread_t));
    if (pool->workers == NULL) {
        free(pool->queue);
        free(pool);
        return NULL;
    }

    // 创建工作者线程
    for (int i = 0; i < config->max_workers; ++i) {
        if (pthread_create(&pool->workers[i], NULL, worker, pool)) {
            fprintf(stderr, "Failed to create worker thread\n");
            break;
        }
        pool->worker_count++;
    }

    return pool;
}

// 初始化日志记录器
static Logger *logger_init(lua_State *L) {
    Logger *logger = malloc(sizeof(Logger));
    if (logger == NULL) {
        return NULL;
    }

    logger->L = L;

    // 创建配置结构体
    LoggerConfig *config = malloc(sizeof(LoggerConfig));
    if (config == NULL) {
        free(logger);
        return NULL;
    }

    // 从Lua获取配置参数
    if (!get_config_from_lua(L, config)) {
        free(config);
        free(logger);
        return NULL;
    }

    // 创建线程池
    logger->pool = create_thread_pool(config);
    if (logger->pool == NULL) {
        free(config);
        free(logger);
        return NULL;
    }

    logger->pool->output = stdout;

    // 初始化内存池
    init_memory_pool(logger);

    return logger;
}

// Lua模块打开函数
int luaopen_logger(lua_State *L) {
    if (initialized) {
        return 0; // 已经初始化过，直接返回
    }

    initialized = true;

    // 创建日志记录器实例
    Logger *logger = logger_init(L);
    if (!logger) {
        return 0; // 初始化失败
    }

    // 创建metatable并设置元方法
    luaL_newmetatable(L, "Logger");
    const luaL_Reg logger_metatable[] = {
        {"record", record},
        {"destroy", destroy},
        {NULL, NULL}
    };
    luaL_setfuncs(L, logger_metatable, 0);

    // 将Logger指针存储在 userdata 中
    lua_pushlightuserdata(L, logger);
    lua_setfield(L, -2, "__ptr");

    // 将 userdata 推入栈顶
    lua_pushvalue(L, -1);

    return 1; // 返回 userdata 给Lua
}

// 记录日志方法
static int record(lua_State *L) {
    Logger *logger = luaL_checkudata(L, 1, "Logger");
    const char *message = luaL_checkstring(L, 2);

    if (!logger || !logger->pool || !logger->pool->running) {
        return luaL_error(L, "Invalid logger instance");
    }

    // 从内存池中获取一个空闲块
    size_t free_index = atomic_load(&logger->pool->memory_pool.free_index) % logger->config->max_memory_pool_blocks;
    LogTask *task = logger->pool->memory_pool.blocks[free_index];

    task->message = malloc(strlen(message) + 1);
    if (!task->message) {
        return luaL_error(L, "Failed to allocate memory for log message");
    }

    strcpy(task->message, message);
    task->length = strlen(message);

    // 将任务加入队列
    size_t tail = atomic_load(&logger->pool->queue.tail);
    size_t next_tail = (tail + 1) % logger->pool->queue.capacity;

    if (next_tail != atomic_load(&logger->pool->queue.head)) {
        logger->pool->queue.tasks[tail] = task;
        atomic_store(&logger->pool->queue.tail, next_tail);
    } else {
        // 队列已满，重试或丢弃
        free(task->message);
        task->message = NULL;
        task->length = 0;

        // 这里可以根据需要实现重试逻辑
        // 例如，等待一段时间后重试
    }

    return 0;
}

// 销毁日志记录器方法
static int destroy(lua_State *L) {
    Logger *logger = luaL_checkudata(L, 1, "Logger");

    if (!logger || !logger->pool || !logger->pool->running) {
        return luaL_error(L, "Invalid logger instance");
    }

    // 停止线程池
    logger->pool->running = 0;

    // 等待所有工作者线程退出
    for (int i = 0; i < logger->pool->worker_count; ++i) {
        pthread_join(logger->pool->workers[i], NULL);
    }

    // 清理任务队列
    free(logger->pool->queue->tasks);
    free(logger->pool->queue);

    // 清理内存池
    for (size_t i = 0; i < logger->config->max_memory_pool_blocks; ++i) {
        if (logger->pool->memory_pool.blocks[i]) {
            free(logger->pool->memory_pool.blocks[i]);
        }
    }
    free(logger->pool->memory_pool.blocks);

    // 清理线程池
    free(logger->pool->workers);
    free(logger->pool);

    // 清理配置
    free(logger->config);

    free(logger);

    return 0;
}