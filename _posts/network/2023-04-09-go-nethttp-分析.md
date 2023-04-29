---
layout:     post
title:      "Go net/http 分析"
subtitle:   "网络"
date:       2023-04-29 11:24:00
author:     "WR"
hidden: false
tags:
- 网络
- Go
---

### 简介

​	Net/http 是 Go 官方提供的网络库，本文主要介绍 net 包的简单使用及源码分析。

### 基本使用示例

#### Client 端

##### GET 请求示例

```go
resp, err := http.Get("http://localhost:8000")
	if err != nil {
		fmt.Printf("get failed, err:%v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("read from resp.Body failed, err:%v\n", err)
		return
	}
	fmt.Print(string(body))
```

##### GET 请求带参数示例

```go
func main() {
    apiUrl := "http://localhost:8000/index"
    // URL param
    data := url.Values{}
    data.Set("name", "rain")
    data.Set("age", "18")
    u, err := url.ParseRequestURI(apiUrl)
    if err != nil {
        fmt.Printf("parse url requestUrl failed, err:%v\n", err)
    }
  
  	// URL encode
    u.RawQuery = data.Encode() 
  
    resp, err := http.Get(u.String())
    if err != nil {
        fmt.Printf("post failed, err:%v\n", err)
        return
    }
    defer resp.Body.Close()
  
    b, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("get resp failed, err:%v\n", err)
        return
    }
    fmt.Println(string(b))
}

```

​		对应的server端参数解析：

```go
func getHandler(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close()
    data := r.URL.Query()
    fmt.Println(data.Get("name"))
    fmt.Println(data.Get("age"))
    answer := `{"status": "ok"}`
    w.Write([]byte(answer))
}
```

##### POST 请求示例

```go
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
)

// net/http post demo

func main() {
    url := "http://localhost:8000/post"
    // 表单数据
    //contentType := "application/x-www-form-urlencoded"
    //data := "name=mi&age=18"
    // json
    contentType := "application/json"
    data := `{"name":"rain","age":18}`
    resp, err := http.Post(url, contentType, strings.NewReader(data))
    if err != nil {
        fmt.Printf("post failed, err:%v\n", err)
        return
    }
    defer resp.Body.Close()
    b, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("get resp failed, err:%v\n", err)
        return
    }
    fmt.Println(string(b))
}

```

​	对应 server 端

```go
func postHandler(w http.ResponseWriter, r *http.Request) {
    defer r.Body.Close()
    // 1. 请求类型是application/x-www-form-urlencoded时解析form数据
    r.ParseForm()
    fmt.Println(r.PostForm) // 打印form数据
    fmt.Println(r.PostForm.Get("name"), r.PostForm.Get("age"))
    // 2. 请求类型是application/json时从r.Body读取数据
    b, err := ioutil.ReadAll(r.Body)
    if err != nil {
        fmt.Printf("read request.Body failed, err:%v\n", err)
        return
    }
    fmt.Println(string(b))
    answer := `{"status": "ok"}`
    w.Write([]byte(answer))
}
```



##### 自定义 client

要管理HTTP客户端的头域、重定向策略和其他设置，创建一个Client：

```go
client := &http.Client{
    CheckRedirect: redirectPolicyFunc,
}
resp, err := client.Get("http://example.com")
// ...
req, err := http.NewRequest("GET", "http://example.com", nil)
// ...
req.Header.Add("If-None-Match", `W/"wyzzy"`)
resp, err := client.Do(req)
```

##### 自定义 Transport

要管理代理、TLS配置、keep-alive、压缩和其他设置，创建一个Transport：

```go
tr := &http.Transport{
    TLSClientConfig:    &tls.Config{RootCAs: pool},
    DisableCompression: true,
}
client := &http.Client{Transport: tr}
resp, err := client.Get("https://example.com")
```



##### Server 端

###### 默认 Server

```go
func main() {
	http.HandleFunc("/", indexHandler)
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// handler echoes r.URL.Path
func indexHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "URL.Path = %q\n", req.URL.Path)
	w.Write([]byte("hello world"))
}
```

###### 自定义 Server

```go
s := &http.Server{
    Addr:           ":8080",
    Handler:        myHandler,
    ReadTimeout:    10 * time.Second,
    WriteTimeout:   10 * time.Second,
    MaxHeaderBytes: 1 << 20,
}
log.Fatal(s.ListenAndServe())
```

###### 自定义路由

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

// Engine is the uni handler for all requests
type Engine struct{}

func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/":
		fmt.Fprintf(w, "URL.Path = %q\n", req.URL.Path)
	case "/hello":
		for k, v := range req.Header {
			fmt.Fprintf(w, "Header[%q] = %q\n", k, v)
		}
	default:
		fmt.Fprintf(w, "404 NOT FOUND: %s\n", req.URL)
	}
}

func main() {
	engine := new(Engine)
	log.Fatal(http.ListenAndServe(":9999", engine))
}
```



### 源码分析

```go
package main

import (
  "fmt"
  "net/http"
)

func index(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "Hello World")
}

func main() {
  http.HandleFunc("/", index)
  http.ListenAndServe(":8080", nil)
}
```

以上是一段简单的服务端注册启动代码，基于以上代码进行层层剖析。



#### 路由注册

http.HandleFunc("/", index) 是路由注册，对应源码如下：

```go
// HandleFunc registers the handler function for the given pattern
// in the DefaultServeMux.
// The documentation for ServeMux explains how patterns are matched.
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}
```

DefaultServeMux 是ServeMux对象实例

```go
// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = &defaultServeMux

var defaultServeMux ServeMux
```

ServeMux 保存了注册的路由与对应处理函数的映射关系

```go
// ServeMux also takes care of sanitizing the URL request path and the Host
// header, stripping the port number and redirecting any request containing . or
// .. elements or repeated slashes to an equivalent, cleaner URL.
type ServeMux struct {
	mu    sync.RWMutex
	m     map[string]muxEntry
	es    []muxEntry // slice of entries sorted from longest to shortest.
	hosts bool       // whether any patterns contain hostnames
}
```

ServeMux 还实现了 Handler 接口，对应的接口方法 ServeHTTP 接收用户请求，对用户路由方法进行分发

```go
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}
```

DefaultServeMux.HandleFunc 对应实现如下，该函数对 handler 参数进行类型转换之后，调用 Handle 进行路由注册

```go
// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	if handler == nil {
		panic("http: nil handler")
	}
	mux.Handle(pattern, HandlerFunc(handler))
}
```

mux.Handle 实现如下

```go
// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("http: invalid pattern")
	}
	if handler == nil {
		panic("http: nil handler")
	}
	if _, exist := mux.m[pattern]; exist {
		panic("http: multiple registrations for " + pattern)
	}

  // 懒加载
	if mux.m == nil {
		mux.m = make(map[string]muxEntry)
	}
	e := muxEntry{h: handler, pattern: pattern}
	mux.m[pattern] = e
  
  // 如果路由是以 / 结尾，则把路由加入到es结构里面，并根据路由名称进行排序
  // es 结构主要用于路由的最长前缀匹配
  // 例如注册路径是 /a/, 当我们访问 /a/b/c 时，先进行精确匹配，没有匹配到则进行最长前缀匹配，匹配到路由 /a/
	if pattern[len(pattern)-1] == '/' {
		mux.es = appendSorted(mux.es, e)
	}

	if pattern[0] != '/' {
		mux.hosts = true
	}
}
```

appendSorted 实现如下，就是对路由进行排序然后放入 []muxEntry 切片当中

```go
func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
   n := len(es)
   i := sort.Search(n, func(i int) bool {
      return len(es[i].pattern) < len(e.pattern)
   })
   if i == n {
      return append(es, e)
   }
   // we now know that i points at where we want to insert
   es = append(es, muxEntry{}) // try to grow the slice in place, any entry works.
   copy(es[i+1:], es[i:])      // Move shorter entries down
   es[i] = e
   return es
}
```



#### 启动服务

http.ListenAndServe(":8080", nil) 启动服务并且监听端口8080，第二个参数这里为 nil，我们也可以传一个实现了 Handler 接口的自定义方法，这样路由就交由我们自己处理。go net 网络库是基于 epoll 模式实现的，epollo 模式是基于异步非阻塞的模型，基于回调函数的编程方式却非常不符合人的的直线思维模式，开发出来的代码的也不便于理解。而golang 基于协程与 epoll 配合，基于同步编程的方式的同时也获得了较好的性能。

一般服务端进程启动都要经历以下几个步骤

- 创建 socket 并设置非阻塞
- bind 绑定并监听本地的一个端口
- 调用 listen 开始监听
- epoll_create 创建一个 epoll 对象
- epoll_etl 将 listen 的 socket 添加到 epoll 中等待连接到来

一次 Golang 的 Listen 调用，相当于在 C 语言中的 socket、bind、listen、epoll_create、epoll_etl 等多次函数调用的效果。



ListenAndServer 使用默认 Server对象调用 ListenAndServe() 方法，我们也可以自定义 Server对象调用 ListenAndServe()

```go
// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServe()
}
```



Server.ListenAndServer

```go
// ListenAndServe always returns a non-nil error. After Shutdown or Close,
// the returned error is ErrServerClosed.
func (srv *Server) ListenAndServe() error {
  // 如果服务已经关闭，返回服务关闭错误
	if srv.shuttingDown() {
		return ErrServerClosed
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
  
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}
```

接下来进入 net.Listen 方法

```go
// parameters.
func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (Listener, error) {
	addrs, err := DefaultResolver.resolveAddrList(ctx, "listen", network, address, nil)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	sl := &sysListener{
		ListenConfig: *lc,
		network:      network,
		address:      address,
	}
	var l Listener
	la := addrs.first(isIPv4)
	switch la := la.(type) {
	case *TCPAddr:
		l, err = sl.listenTCP(ctx, la)
	case *UnixAddr:
		l, err = sl.listenUnix(ctx, la)
	default:
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: address}}
	}
	if err != nil {
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: err} // l is non-nil interface containing nil pointer
	}
	return l, nil
}
```

经过路径 sl.listenTCP(ctx, la)  -> internetSocket -> socket 进入到 socket 函数

```go
// socket returns a network file descriptor that is ready for
// asynchronous I/O using the network poller.
func socket(ctx context.Context, net string, family, sotype, proto int, ipv6only bool, laddr, raddr sockaddr, ctrlFn func(string, string, syscall.RawConn) error) (fd *netFD, err error) {
	s, err := sysSocket(family, sotype, proto)
	if err != nil {
		return nil, err
	}
	if err = setDefaultSockopts(s, family, sotype, ipv6only); err != nil {
		poll.CloseFunc(s)
		return nil, err
	}
	if fd, err = newFD(s, family, sotype, net); err != nil {
		poll.CloseFunc(s)
		return nil, err
	}

	// This function makes a network file descriptor for the
	// following applications:
	//
	// - An endpoint holder that opens a passive stream
	//   connection, known as a stream listener
	//
	// - An endpoint holder that opens a destination-unspecific
	//   datagram connection, known as a datagram listener
	//
	// - An endpoint holder that opens an active stream or a
	//   destination-specific datagram connection, known as a
	//   dialer
	//
	// - An endpoint holder that opens the other connection, such
	//   as talking to the protocol stack inside the kernel
	//
	// For stream and datagram listeners, they will only require
	// named sockets, so we can assume that it's just a request
	// from stream or datagram listeners when laddr is not nil but
	// raddr is nil. Otherwise we assume it's just for dialers or
	// the other connection holders.

	if laddr != nil && raddr == nil {
		switch sotype {
		case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
			if err := fd.listenStream(laddr, listenerBacklog(), ctrlFn); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		case syscall.SOCK_DGRAM:
			if err := fd.listenDatagram(laddr, ctrlFn); err != nil {
				fd.Close()
				return nil, err
			}
			return fd, nil
		}
	}
	if err := fd.dial(ctx, laddr, raddr, ctrlFn); err != nil {
		fd.Close()
		return nil, err
	}
	return fd, nil
}
```

上述代码通过 sysSocket 创建 socket，代码解释见注释

```go
// Wrapper around the socket system call that marks the returned file
// descriptor as nonblocking and close-on-exec.
func sysSocket(family, sotype, proto int) (int, error) {
	// See ../syscall/exec_unix.go for description of ForkLock.
	syscall.ForkLock.RLock()
  // 通过系统调用创建socket
	s, err := socketFunc(family, sotype, proto)
	if err == nil {
		syscall.CloseOnExec(s)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
  // 设置 socket 为非阻塞
	if err = syscall.SetNonblock(s, true); err != nil {
		poll.CloseFunc(s)
		return -1, os.NewSyscallError("setnonblock", err)
	}
	return s, nil
}
```

然后通过 listenStream 进行 bind 、listen 操作

```go
func (fd *netFD) listenStream(laddr sockaddr, backlog int, ctrlFn func(string, string, syscall.RawConn) error) error {
	var err error
	if err = setDefaultListenerSockopts(fd.pfd.Sysfd); err != nil {
		return err
	}
	var lsa syscall.Sockaddr
	if lsa, err = laddr.sockaddr(fd.family); err != nil {
		return err
	}
	if ctrlFn != nil {
		c, err := newRawConn(fd)
		if err != nil {
			return err
		}
		if err := ctrlFn(fd.ctrlNetwork(), laddr.String(), c); err != nil {
			return err
		}
	}
  // 绑定端口
	if err = syscall.Bind(fd.pfd.Sysfd, lsa); err != nil {
		return os.NewSyscallError("bind", err)
	}
  // listen 监听
	if err = listenFunc(fd.pfd.Sysfd, backlog); err != nil {
		return os.NewSyscallError("listen", err)
	}
  
  // 初始化socket与异步IO相关的内容
	if err = fd.init(); err != nil {
		return err
	}
	lsa, _ = syscall.Getsockname(fd.pfd.Sysfd)
	fd.setAddr(fd.addrFunc()(lsa), nil)
	return nil
}
```

接下来进入 srv.Serve() 方法

```go
func (srv *Server) Serve(l net.Listener) error {
	if fn := testHookServerServe; fn != nil {
		fn(srv, l) // call hook with unwrapped listener
	}

	origListener := l
	l = &onceCloseListener{Listener: l}
	defer l.Close()

	if err := srv.setupHTTP2_Serve(); err != nil {
		return err
	}

	if !srv.trackListener(&l, true) {
		return ErrServerClosed
	}
	defer srv.trackListener(&l, false)

	baseCtx := context.Background()
	if srv.BaseContext != nil {
		baseCtx = srv.BaseContext(origListener)
		if baseCtx == nil {
			panic("BaseContext returned a nil context")
		}
	}

	var tempDelay time.Duration // how long to sleep on accept failure

	ctx := context.WithValue(baseCtx, ServerContextKey, srv)
	for {
		rw, err := l.Accept()
		if err != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("http: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		connCtx := ctx
		if cc := srv.ConnContext; cc != nil {
			connCtx = cc(connCtx, rw)
			if connCtx == nil {
				panic("ConnContext returned nil")
			}
		}
		tempDelay = 0
		c := srv.newConn(rw)
		c.setState(c.rwc, StateNew, runHooks) // before Serve can return
		go c.serve(connCtx)
	}
}
```

通过 for 循环不断 accept 用户请求，这里有一个**指数退避策略**的用法。如果`l.Accept()`调用返回错误，我们判断该错误是不是临时性地（`ne.Temporary()`）。如果是临时性错误，`Sleep`一小段时间后重试，每发生一次临时性错误，`Sleep`的时间翻倍，最多`Sleep` 1s。获得新连接后，将其封装成一个`conn`对象（`srv.newConn(rw)`），创建一个 goroutine 运行其`serve()`方法。由于每次都是创建一个新的Goroutine处理请求，如果当前 HTTP 服务接收到了海量的请求，会在内部创建大量的 Goroutine，这可能会使整个服务质量明显降低无法处理请求。



接收用户请求

```go
// Accept wraps the accept network call.
func (fd *FD) Accept() (int, syscall.Sockaddr, string, error) {
	if err := fd.readLock(); err != nil {
		return -1, nil, "", err
	}
	defer fd.readUnlock()

	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return -1, nil, "", err
	}
	for {
    // 调用 accept 系统调用接收一个连接
		s, rsa, errcall, err := accept(fd.Sysfd)
    // 接收到了连接就返回它
		if err == nil {
			return s, rsa, "", err
		}
		switch err {
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
      // 如果没有获取到，那就把协程给阻塞起来
			if fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		case syscall.ECONNABORTED:
			// This means that a socket on the listen
			// queue was closed before we Accept()ed it;
			// it's a silly error, so try again.
			continue
		}
		return -1, nil, errcall, err
	}
}
```



阻塞当前协程

如果调用 accept 方法的时候，客户端的连接请求一个都没有过来， accept 系统调用会返回syscall.EAGAIN。这时候golang 会把当前协程阻塞起来。

```go
//file: internal/poll/fd_poll_runtime.go
func (pd *pollDesc) waitRead(isFile bool) error {
 return pd.wait('r', isFile)
}
func (pd *pollDesc) wait(mode int, isFile bool) error {
 if pd.runtimeCtx == 0 {
  return errors.New("waiting for unsupported file type")
 }
 res := runtime_pollWait(pd.runtimeCtx, mode)
 return convertErr(res, isFile)
}
```

runtime_pollWait 的源码在 runtime/netpoll.go 下。gopark（协程的阻塞）就是在这里完成的。

```go
//file:runtime/netpoll.go
//go:linkname poll_runtime_pollWait internal/poll.runtime_pollWait
func poll_runtime_pollWait(pd *pollDesc, mode int) int {
    ...
    for !netpollblock(pd, int32(mode), false) {
    }
}

func netpollblock(pd *pollDesc, mode int32, waitio bool) bool {
    ...
    if waitio || netpollcheckerr(pd, mode) == 0 {
        gopark(netpollblockcommit, unsafe.Pointer(gpp), waitReasonIOWait, traceEvGoBlockNet, 5)
    }
}
```

gopark 这个函数就是 golang 内部阻塞协程的入口。



##### 将新连接添加到 epoll 中

假如客户端连接已经到来了的情况。这时 fd.pfd.Accept 会返回新建的连接。然后会将该新连接也一并加入到 epoll 中进行高效的事件管理。

```go
//file:net/fd_unix.go
func (fd *netFD) accept() (netfd *netFD, err error) {
 //3.1 接收一个连接
 //3.2 如果连接没有到达阻塞当前协程
 d, rsa, errcall, err := fd.pfd.Accept()

 //3.2 将新到的连接也添加到 epoll 中进行管理
 netfd, err = newFD(d, fd.family, fd.sotype, fd.net);
 netfd.init();

 ...
 return netfd, nil
}
```

我们来看 netfd.init

```go
//file:internal/poll/fd_poll_runtime.go
func (pd *pollDesc) init(fd *FD) error {
 ...
 ctx, errno := runtime_pollOpen(uintptr(fd.Sysfd))
 ...
}
```

runtime_pollOpen 这个runtime 函数我们在上面的 2.4 节介绍过了，就是把文件句柄添加到 epoll 对象中。

```go
//file:runtime/netpoll_epoll.go
//go:linkname poll_runtime_pollOpen internal/poll.runtime_pollOpen
func poll_runtime_pollOpen(fd uintptr) (*pollDesc, int) {
 ...
 errno = netpollopen(fd, pd)
 return pd, int(errno)
}

func netpollopen(fd uintptr, pd *pollDesc) int32 {
 var ev epollevent
 ev.events = _EPOLLIN | _EPOLLOUT | _EPOLLRDHUP | _EPOLLET
 *(**pollDesc)(unsafe.Pointer(&ev.data)) = pd

 //新连接的 socket 也被添加到了 epoll 中。
 return -epollctl(epfd, _EPOLL_CTL_ADD, int32(fd), &ev)
}
```



#### Read 和 Write 过程

###### Read 过程

```go
//file:/Users/zhangyanfei/sdk/go1.14.4/src/net/net.go
func (c *conn) Read(b []byte) (int, error) {
 ...
 n, err := c.fd.Read(b)
}
```

Read 函数会进入到 FD 的 Read 中。在这个函数内部调用 Read 系统调用来读取数据。如果数据还尚未到达则也是把自己阻塞起来。

```go
//file:internal/poll/fd_unix.go
func (fd *FD) Read(p []byte) (int, error) {
 for {
  //调用 Read 系统调用
  n, err := syscall.Read(fd.Sysfd, p)
  if err != nil {
   n = 0

   //将自己添加到 epoll 中等待事件，然后阻塞掉。
   if err == syscall.EAGAIN && fd.pd.pollable() {
    if err = fd.pd.waitRead(fd.isFile); err == nil {
     continue
    }
   }
  ...... 
 }  
}
```

其中 waitRead 是如何将当前协程阻塞掉的，这个和我们前面 3.2 节介绍的是一样的，就不过多展开叙述了。



###### Write 过程

Write 的大体过程和 Read 是类似的。先是调用 Write 系统调用发送数据，如果内核发送缓存区不足的时候，就把自己先阻塞起来，然后等可写时间发生的时候再继续发送。其源码入口位于 net/net.go。

```go
//file:net/net.go
func (c *conn) Write(b []byte) (int, error) {
 ...
 n, err := c.fd.Write(b)
}
```

```go
//file:internal/poll/fd_unix.go
func (fd *FD) Write(p []byte) (int, error) {
 for {
  n, err := syscall.Write(fd.Sysfd, p[nn:max])
  if err == syscall.EAGAIN && fd.pd.pollable() {
   if err = fd.pd.waitWrite(fd.isFile); err == nil {
    continue
   }
  }
 }
}
```

```go
//file:internal/poll/fd_poll_runtime.go
func (pd *pollDesc) waitWrite(isFile bool) error {
 return pd.wait('w', isFile)
}
```

pd.wait 之后的事情就又和 之前介绍的过程一样了。调用 runtime_pollWait 来讲当前协程阻塞掉。

```go
func (pd *pollDesc) wait(mode int, isFile bool) error {
 ...
 res := runtime_pollWait(pd.runtimeCtx, mode)
}
```

#### 数据处理

解析完协议之后会对数据根据默认路由或者用户自定义路由处理对象对数据进行处理，代码如下

```go
// HTTP cannot have multiple simultaneous active requests.[*]
		// Until the server replies to this request, it can't read another,
		// so we might as well run the handler in this goroutine.
		// [*] Not strictly true: HTTP pipelining. We could let them all process
		// in parallel even if their responses need to be serialized.
		// But we're not going to implement HTTP pipelining because it
		// was never deployed in the wild and the answer is HTTP/2.
		// 处理用户请求
		serverHandler{c.server}.ServeHTTP(w, w.req)
		w.cancelCtx()
		if c.hijacked() {
			return
		}
```



引用

https://pkg.go.dev/net/http

https://draveness.me/golang/docs/part4-advanced/ch09-stdlib/golang-net-http/

https://darjun.github.io/2021/07/13/in-post/godailylib/nethttp/

https://geektutu.com/post/gee-day1.html

[goland  是如何对 epoll 进行封装的]: https://mp.weixin.qq.com/s?src=11&amp;timestamp=1682345047&amp;ver=4488&amp;signature=LcfiLzepLl0fwhZdM*rqwfPO-n9ao4xYs-InSUuMJ-7r5l6CosOR7v4h0xJupDc1KvtEHyYbltuMxvLPvCn7wZ3**dEdxh*eYTVBjh6JmBypAOdKTLR3qmLBh3izDsQq&amp;new=1



