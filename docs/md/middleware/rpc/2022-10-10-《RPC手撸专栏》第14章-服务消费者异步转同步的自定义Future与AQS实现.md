---
title: 第14章：服务消费者异步转同步的自定义Future与AQS实现
pay: https://articles.zsxq.com/id_6v8wcbaaitg4.html
---

# 《RPC手撸专栏》第14章：服务消费者异步转同步的自定义Future与AQS实现

作者：冰河
<br/>星球：[http://m6z.cn/6aeFbs](http://m6z.cn/6aeFbs)
<br/>博客：[https://binghe001.github.io](https://binghe001.github.io)

> 沉淀，成长，突破，帮助他人，成就自我。

**大家好，我是冰河~~**

直接用while(true)循环的方式实现异步转同步还是有点low啊，咱还是升级为使用CompletableFuture吧。

## 一、前言

`while(true)循环实现异步转同步，不仅low，还极大的占用CPU资源，换，必须换！`

在前面的章节中，我们在服务消费者一端基于while(true)循环的方式实现了异步转同步的调用方式，能够在服务消费者屏蔽掉基于Netty连接服务提供者的实现细节的前提下，直接获取服务提供者调用真实方法的结果。

但是，这里存在着一个很明显的问题，就是：服务消费者端实现异步转同步时，使用的是while(true)循环的方式，也就是使用了一个死循环，代码如下所示。

```java
public Object sendRequest(RpcProtocol<RpcRequest> protocol){
	//################省略其他代码#####################
    //异步转同步
    while (true){
        RpcProtocol<RpcResponse> responseRpcProtocol = pendingResponse.remove(requestId);
        if (responseRpcProtocol != null){
            return responseRpcProtocol.getBody().getResult();
        }
    }
}
```

上述代码会不断尝试去获取数据，如果未获取到数据，则一直尝试，如果获取到数据，直接返回。如果在使用RPC框架调用远程服务的过程中，出现了网络延迟或者远程服务不可用时，则while(true)死循环会一直尝试获取数据，并且调用sendRequest()方法向服务提供者发送数据时，都会在死循环中一直进行尝试，进而导致程序不可用。

基础好一点的小伙伴可能会想到使用超时，比如类似下面代码的方式。

```java
public Object sendRequest(RpcProtocol<RpcRequest> protocol){
	//################省略其他代码#####################
    int startTime = System.currentTimeMillis();
    //异步转同步
    while (true){
        //模拟5秒后超时退出
        if(System.currentTimeMillis() - startTime >= 5000){
            break;
        }
        RpcProtocol<RpcResponse> responseRpcProtocol = pendingResponse.remove(requestId);
        if (responseRpcProtocol != null){
            return responseRpcProtocol.getBody().getResult();
        }
    }
}
```

这种方式在一定程度上能够缓解while(true)死循环带来的问题，但是还是那句话，Low不Low啊？真实RPC框架里谁会这么搞呢？不行，换，必须换！！

## 二、目标

`异步转同步，换掉while(true)循环，使用CompletableFuture搞定！`

其实，在Java中提供了很多类似异步转同步的实现方式，比如JDK中提供的Future接口，在某种程度上来说，就可以实现异步转同步的功能，例如下面的代码片段所示。

```java
ExecutorService threadPool = Executors.newFixedThreadPool(3);
Future<String> future = threadPool.submit(() -> {
    return "binghe";
});
System.out.println(future.get());
```

将任务提交到线程池后，返回一个Future对象，通过Future对象的get()方法就能够获取到线程池中任务的返回结果。

这里，调用Future的get()方法就会被阻塞，直到线程池中的任务返回结果数据为止。从Java的JDK1.8版本开始，提供了功能更为强大的CompletableFuture类，CompletableFuture类实现了Future接口。

本章，我们就基于Java中的CompletableFuture类和AQS实现服务消费者异步转同步的升级。

## 三、设计

`如果让你基于Java中的CompletableFuture类和AQS实现服务消费者异步转同步的升级，你会怎么设计呢？`

服务消费者真正实现异步转同步时，会基于Java中的CompletableFuture类实现自定义的Future，并结合AQS实现，设计流程如图14-1所示。

![图14-1 异步转同步升级](https://binghe001.github.io/assets/images/middleware/rpc/rpc-2022-10-10-001.png)

由图14-1可以看出：

（1）外部服务调用服务消费者的方法向服务提供者发送数据时，依旧屏蔽了基于Netty的连接细节，外部服务调用消费者发送数据的方法后，立刻接收一个自定义的Future，通过Future的get()方法获取真实数据。

（2）服务消费者向服务提供者传递必要的参数，发起异步请求，如果外部服务调用了自定义Future的get()方法，则外部服务的线程会阻塞。

（3）服务提供者接收到服务消费者发送过来的数据后，调用真实方法，并接收真实方法返回的结果数据。

（4）服务提供者接收到真实方法返回的结果数据后，向服务消费者响应结果数据。

（5）服务消费者接收到服务提供者响应的结果数据后，唤醒阻塞的线程，并向外部服务响应结果数据。

（6）外部服务会通过自定义Future的get()方法获取到最终的结果数据。

**注意：通过自定义的Future获取结果数据时，支持阻塞获取和超时阻塞获取两种方式。**

## 四、实现

`说了这么多，异步转同步的升级要怎么实现呢？`

## 查看完整文章

加入[冰河技术](http://m6z.cn/6aeFbs)知识星球，解锁完整技术文章与完整代码