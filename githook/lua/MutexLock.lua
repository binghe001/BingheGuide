---
--- Created by binghe.
---

local ffi = require("ffi")
local MutexLock = {}
MutexLock.__index = MutexLock

-- 引入 pthread 库
ffi.cdef[[
typedef struct {
    int __lock;
    unsigned int __count;
    unsigned int __owner;
    unsigned int __nusers;
} pthread_mutex_t;

int pthread_mutex_init(pthread_mutex_t *mutex, const void *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
]]

-- 构造函数
function MutexLock.new()
    local self = setmetatable({}, MutexLock)
    self.lock = ffi.new("pthread_mutex_t[1]")
    assert(ffi.C.pthread_mutex_init(self.lock, nil) == 0, "Failed to initialize mutex")
    self.is_locked = false
    return self
end

-- 加锁函数
function MutexLock:lock(timeout)
    local result
    local start_time = os.clock()

    while true do
        result = ffi.C.pthread_mutex_trylock(self.lock)

        if result == 0 then
            self.is_locked = true
            return true
        elseif os.clock() - start_time >= timeout then
            return false -- 超时
        end
        -- 使用更优的时间间隔来避免 CPU 占用过高
        os.execute("sleep 0.001") -- 等待 1 毫秒
    end
end

-- 释放锁函数
function MutexLock:unlock()
    if self.is_locked then
        assert(ffi.C.pthread_mutex_unlock(self.lock) == 0, "Failed to unlock mutex")
        self.is_locked = false
    else
        error("Mutex is not locked")
    end
end

-- 销毁互斥锁
function MutexLock:destroy()
    assert(ffi.C.pthread_mutex_destroy(self.lock) == 0, "Failed to destroy mutex")
end

return MutexLock