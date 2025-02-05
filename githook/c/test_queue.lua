local Queue = require("Queue")

-- 创建一个容量为 10 的队列
local q = Queue.new(10)

-- 入队操作
q:enqueue("Hello")
q:enqueue("World")

-- 查看队首元素
print(q:peek())  -- 输出: Hello

-- 出队操作
print(q:dequeue())  -- 输出: Hello
print(q:dequeue())  -- 输出: World

-- 获取队列长度
print(q:length())  -- 输出: 0