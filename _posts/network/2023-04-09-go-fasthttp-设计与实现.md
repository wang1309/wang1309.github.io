---
layout:     post
title:      "Go fasthttp 设计与实现"
subtitle:   "网络"
date:       2023-04-29 17:32:00
author:     "WR"
hidden: false
tags:
- 网络
- Go
---

#### Fasthttp 是什么？

**官方介绍：**fasthttp是为一些高性能边缘情况而设计的。除非您的服务器/客户端需要处理数千个每秒的小到中等请求并需要一致的低毫秒响应时间，否则fasthttp可能不适合您。对于大多数情况，net/http更好，因为它更易于使用并且可以处理更多情况。对于大多数情况，您甚至不会注意到性能差异。

目前，VertaMedia 在生产环境中成功地使用fasthttp，每个物理服务器可以提供高达200K rps的服务，并支持超过1.5M个并发keep-alive连接。

#### Fasthttp 为什么比 net/http 快？

- 使用连接池，不再像 net/http 一样每accept一个请求就分配一个新的goroutine处理请求（在请求量大的时候会有性能问题）
- 对象池化
- 使用 []byte 缓冲池，减少内存分配
- 避免 []byte 和 string 之间的转化，[]byte 和 string 和转化会产生内存拷贝，fasthttp 实现了无需内存拷贝的转化方法，具体见代码  [b2s](https://github.com/valyala/fasthttp/blob/master/b2s_old.go) 和 [s2b](https://github.com/valyala/fasthttp/blob/master/s2b_old.go)

#### 源码解析

```go
func main() { 
 if err := fasthttp.ListenAndServe(":8088", requestHandler); err != nil {
  log.Fatalf("Error in ListenAndServe: %s", err)
 }
}

func requestHandler(ctx *fasthttp.RequestCtx) {
 fmt.Fprintf(ctx, "Hello, world!\n\n")
}
```

##### ListenAndServe 工作流程

- 监听端口，获取 listen 连接，这个和 net/http 一致
- 循环监听用户请求
- 获取到连接之后首先会去 ready 队列里获取 workerChan，获取不到就会去对象池获取
- 将监听的连接传入到 workerChan 的 channel 中
- 有一个协程执行 workerFunc 循环读取 workerChan 的 channel，获取到连接对象后会对请求进行处理



ListenAndServer 方法

```go
// Accepted connections are configured to enable TCP keep-alives.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}
```

​	获取 listen 监听对象，调用 server 进行处理



###### Server 方法

```go
// 为了便于分析只保留了核心代码
// Serve serves incoming connections from the given listener.
//
// Serve blocks until the given listener returns permanent error.
func (s *Server) Serve(ln net.Listener) error {
	var lastOverflowErrorTime time.Time
	var lastPerIPErrorTime time.Time
	var c net.Conn
	var err error

  // 获取最大并发数，默认是 256 * 1024个
	maxWorkersCount := s.getConcurrency()

	...

  // 初始化 workerPool
	wp := &workerPool{
		WorkerFunc:            s.serveConn, // 设置连接处理函数
		MaxWorkersCount:       maxWorkersCount, // 设置最大并发数
		LogAllErrors:          s.LogAllErrors,
		MaxIdleWorkerDuration: s.MaxIdleWorkerDuration, // 设置单个连接对象的最大空闲时间
		Logger:                s.logger(),
		connState:             s.setState,
	}
  // 启动 workpool ，里面 有一个 clean 方法，默认每10s清理一下超过最大空闲时间的链接
	wp.Start()

	// Count our waiting to accept a connection as an open connection.
	// This way we can't get into any weird state where just after accepting
	// a connection Shutdown is called which reads open as 0 because it isn't
	// incremented yet.
	atomic.AddInt32(&s.open, 1)
	defer atomic.AddInt32(&s.open, -1)

	for {
    // accept 请求，这里和 net/http 一致
		if c, err = acceptConn(s, ln, &lastPerIPErrorTime); err != nil {
			wp.Stop()
			if err == io.EOF {
				return nil
			}
			return err
		}
		s.setState(c, StateNew)
		atomic.AddInt32(&s.open, 1)
    // 处理连接
		if !wp.Serve(c) {
			...
		}
		c = nil
	}
}
```

​	首先初始化 workpool ，设置最大并发数，连接处理函数，空闲连接清理任务。然后是获取用户请求，最后交由

​	Serve 方法对请求进行处理，如果超过最大并发数则返回503。



###### wp.serve 方法

```go
func (wp *workerPool) Serve(c net.Conn) bool {
  // 获取连接
	ch := wp.getCh()
	if ch == nil {
		return false
	}
  // 把请求对象传递给channel，连接处理函数对连接进行处理
	ch.ch <- c
	return true
}
```



###### wp.getCh() 方法

```go
func (wp *workerPool) getCh() *workerChan {
	var ch *workerChan
	createWorker := false

	wp.lock.Lock()
  // 获取空闲连接
	ready := wp.ready
	n := len(ready) - 1
	if n < 0 {
		if wp.workersCount < wp.MaxWorkersCount {
			createWorker = true
			wp.workersCount++
		}
	} else {
		ch = ready[n]
		ready[n] = nil
		wp.ready = ready[:n]
	}
	wp.lock.Unlock()

  
	if ch == nil {
		if !createWorker {
			return nil
		}
    // 空闲连接为空则从对象池获取
		vch := wp.workerChanPool.Get()
		ch = vch.(*workerChan)
    // 启动协程调用处理函数，这个函数用于对连接对象进行处理
    // 处理完成后把对象放回对象池
		go func() {
			wp.workerFunc(ch)
			wp.workerChanPool.Put(vch)
		}()
	}
	return ch
}
```

​		getCh 先从空闲队列获取 workerChan，获取不到则从对象池获取。并且开启一个协程调用 workerFunc 方法，该方法		阻塞等待连接对象，并进行后续请求的处理。



###### 	wp.workerFunc 方法

```go
func (wp *workerPool) workerFunc(ch *workerChan) {
	var c net.Conn

	var err error
  // 读取 ch
	for c = range ch.ch {
    // 这个 nil 是 workerPool 在异步调用 clean 方法检查该 workerChan 空闲时间超长了就会往 channel 中传			// 入一个 nil
		if c == nil {
			break
		}

    // 调用初始化时候注册的处理函数
		if err = wp.WorkerFunc(c); err != nil && err != errHijacked {
			errStr := err.Error()
			if wp.LogAllErrors || !(strings.Contains(errStr, "broken pipe") ||
				strings.Contains(errStr, "reset by peer") ||
				strings.Contains(errStr, "request headers: small read buffer") ||
				strings.Contains(errStr, "unexpected EOF") ||
				strings.Contains(errStr, "i/o timeout") ||
				errors.Is(err, ErrBadTrailer)) {
				wp.Logger.Printf("error when serving connection %q<->%q: %v", c.LocalAddr(), c.RemoteAddr(), err)
			}
		}
		if err == errHijacked {
			wp.connState(c, StateHijacked)
		} else {
			_ = c.Close()
			wp.connState(c, StateClosed)
		}
		c = nil

    // 请求完成workerChan放回空闲队列
		if !wp.release(ch) {
			break
		}
	}

	wp.lock.Lock()
	wp.workersCount--
	wp.lock.Unlock()
}

func (wp *workerPool) release(ch *workerChan) bool {
	ch.lastUseTime = time.Now()
	wp.lock.Lock()
	if wp.mustStop {
		wp.lock.Unlock()
		return false
	}
	wp.ready = append(wp.ready, ch)
	wp.lock.Unlock()
	return true
}
```

等待连接对象到来调用 WorkerFunc 对连接进行处理，处理完成后释放  workerChan 对象。



###### wp.WorkerFunc(c) 对应注册的 serveConn 方法

```go
func (s *Server) serveConn(c net.Conn) (err error) {
	defer s.serveConnCleanup()
	atomic.AddUint32(&s.concurrency, 1)

	var proto string
	if proto, err = s.getNextProto(c); err != nil {
		return
	}
	if handler, ok := s.nextProtos[proto]; ok {
		// Remove read or write deadlines that might have previously been set.
		// The next handler is responsible for setting its own deadlines.
		if s.ReadTimeout > 0 || s.WriteTimeout > 0 {
			if err := c.SetDeadline(zeroTime); err != nil {
				panic(fmt.Sprintf("BUG: error in SetDeadline(zeroTime): %v", err))
			}
		}

		return handler(c)
	}

	serverName := s.getServerName()
	connRequestNum := uint64(0)
	connID := nextConnID()
	connTime := time.Now()
	maxRequestBodySize := s.MaxRequestBodySize
	if maxRequestBodySize <= 0 {
		maxRequestBodySize = DefaultMaxRequestBodySize
	}
	writeTimeout := s.WriteTimeout
	previousWriteTimeout := time.Duration(0)

	// 从对象池获取 ctx
	// fasthttp 通过使用对象池减少内存的创建与回收从而提高程序性能
	ctx := s.acquireCtx(c)
	ctx.connTime = connTime
	isTLS := ctx.IsTLS()
	var (
		br *bufio.Reader
		bw *bufio.Writer

		timeoutResponse  *Response
		hijackHandler    HijackHandler
		hijackNoResponse bool

		connectionClose bool

		continueReadingRequest = true
	)
	for {
		connRequestNum++

		// If this is a keep-alive connection set the idle timeout.
		if connRequestNum > 1 {
			if d := s.idleTimeout(); d > 0 {
				if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
					break
				}
			}
		}

		if !s.ReduceMemoryUsage || br != nil {
			if br == nil {
				br = acquireReader(ctx)
			}

			// If this is a keep-alive connection we want to try and read the first bytes
			// within the idle time.
			if connRequestNum > 1 {
				var b []byte
				b, err = br.Peek(1)
				if len(b) == 0 {
					// If reading from a keep-alive connection returns nothing it means
					// the connection was closed (either timeout or from the other side).
					if err != io.EOF {
						err = ErrNothingRead{err}
					}
				}
			}
		} else {
			// If this is a keep-alive connection acquireByteReader will try to peek
			// a couple of bytes already so the idle timeout will already be used.
			br, err = acquireByteReader(&ctx)
		}

		ctx.Request.isTLS = isTLS
		ctx.Response.Header.noDefaultContentType = s.NoDefaultContentType
		ctx.Response.Header.noDefaultDate = s.NoDefaultDate

		// Secure header error logs configuration
		ctx.Request.Header.secureErrorLogMessage = s.SecureErrorLogMessage
		ctx.Response.Header.secureErrorLogMessage = s.SecureErrorLogMessage
		ctx.Request.secureErrorLogMessage = s.SecureErrorLogMessage
		ctx.Response.secureErrorLogMessage = s.SecureErrorLogMessage

		if err == nil {
			s.setState(c, StateActive)

			if s.ReadTimeout > 0 {
				if err := c.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
					break
				}
			} else if s.IdleTimeout > 0 && connRequestNum > 1 {
				// If this was an idle connection and the server has an IdleTimeout but
				// no ReadTimeout then we should remove the ReadTimeout.
				if err := c.SetReadDeadline(zeroTime); err != nil {
					break
				}
			}
			if s.DisableHeaderNamesNormalizing {
				ctx.Request.Header.DisableNormalizing()
				ctx.Response.Header.DisableNormalizing()
			}

			// Reading Headers.
			//
			// If we have pipeline response in the outgoing buffer,
			// we only want to try and read the next headers once.
			// If we have to wait for the next request we flush the
			// outgoing buffer first so it doesn't have to wait.
			if bw != nil && bw.Buffered() > 0 {
				err = ctx.Request.Header.readLoop(br, false)
				if err == errNeedMore {
					err = bw.Flush()
					if err != nil {
						break
					}

					err = ctx.Request.Header.Read(br)
				}
			} else {
				err = ctx.Request.Header.Read(br)
			}

			if err == nil {
				if onHdrRecv := s.HeaderReceived; onHdrRecv != nil {
					reqConf := onHdrRecv(&ctx.Request.Header)
					if reqConf.ReadTimeout > 0 {
						deadline := time.Now().Add(reqConf.ReadTimeout)
						if err := c.SetReadDeadline(deadline); err != nil {
							panic(fmt.Sprintf("BUG: error in SetReadDeadline(%v): %v", deadline, err))
						}
					}
					if reqConf.MaxRequestBodySize > 0 {
						maxRequestBodySize = reqConf.MaxRequestBodySize
					} else if s.MaxRequestBodySize > 0 {
						maxRequestBodySize = s.MaxRequestBodySize
					} else {
						maxRequestBodySize = DefaultMaxRequestBodySize
					}
					if reqConf.WriteTimeout > 0 {
						writeTimeout = reqConf.WriteTimeout
					} else {
						writeTimeout = s.WriteTimeout
					}
				}
				// read body
				if s.StreamRequestBody {
					err = ctx.Request.readBodyStream(br, maxRequestBodySize, s.GetOnly, !s.DisablePreParseMultipartForm)
				} else {
					err = ctx.Request.readLimitBody(br, maxRequestBodySize, s.GetOnly, !s.DisablePreParseMultipartForm)
				}
			}

			if (s.ReduceMemoryUsage && br.Buffered() == 0) || err != nil {
				releaseReader(s, br)
				br = nil
			}
		}

		if err != nil {
			if err == io.EOF {
				err = nil
			} else if nr, ok := err.(ErrNothingRead); ok {
				if connRequestNum > 1 {
					// This is not the first request and we haven't read a single byte
					// of a new request yet. This means it's just a keep-alive connection
					// closing down either because the remote closed it or because
					// or a read timeout on our side. Either way just close the connection
					// and don't return any error response.
					err = nil
				} else {
					err = nr.error
				}
			}

			if err != nil {
				bw = s.writeErrorResponse(bw, ctx, serverName, err)
			}
			break
		}

		// 'Expect: 100-continue' request handling.
		// See https://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html#sec8.2.3 for details.
		if ctx.Request.MayContinue() {

			// Allow the ability to deny reading the incoming request body
			if s.ContinueHandler != nil {
				if continueReadingRequest = s.ContinueHandler(&ctx.Request.Header); !continueReadingRequest {
					if br != nil {
						br.Reset(ctx.c)
					}

					ctx.SetStatusCode(StatusExpectationFailed)
				}
			}

			if continueReadingRequest {
				if bw == nil {
					bw = acquireWriter(ctx)
				}

				// Send 'HTTP/1.1 100 Continue' response.
				_, err = bw.Write(strResponseContinue)
				if err != nil {
					break
				}
				err = bw.Flush()
				if err != nil {
					break
				}
				if s.ReduceMemoryUsage {
					releaseWriter(s, bw)
					bw = nil
				}

				// Read request body.
				if br == nil {
					br = acquireReader(ctx)
				}

				if s.StreamRequestBody {
					err = ctx.Request.ContinueReadBodyStream(br, maxRequestBodySize, !s.DisablePreParseMultipartForm)
				} else {
					err = ctx.Request.ContinueReadBody(br, maxRequestBodySize, !s.DisablePreParseMultipartForm)
				}
				if (s.ReduceMemoryUsage && br.Buffered() == 0) || err != nil {
					releaseReader(s, br)
					br = nil
				}
				if err != nil {
					bw = s.writeErrorResponse(bw, ctx, serverName, err)
					break
				}
			}
		}

		// store req.ConnectionClose so even if it was changed inside of handler
		connectionClose = s.DisableKeepalive || ctx.Request.Header.ConnectionClose()

		if serverName != "" {
			ctx.Response.Header.SetServer(serverName)
		}
		ctx.connID = connID
		ctx.connRequestNum = connRequestNum
		ctx.time = time.Now()

		// If a client denies a request the handler should not be called
		if continueReadingRequest {
			s.Handler(ctx)
		}

		timeoutResponse = ctx.timeoutResponse
		if timeoutResponse != nil {
			// Acquire a new ctx because the old one will still be in use by the timeout out handler.
			ctx = s.acquireCtx(c)
			timeoutResponse.CopyTo(&ctx.Response)
		}

		if ctx.IsHead() {
			ctx.Response.SkipBody = true
		}

		hijackHandler = ctx.hijackHandler
		ctx.hijackHandler = nil
		hijackNoResponse = ctx.hijackNoResponse && hijackHandler != nil
		ctx.hijackNoResponse = false

		if writeTimeout > 0 {
			if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				panic(fmt.Sprintf("BUG: error in SetWriteDeadline(%v): %v", writeTimeout, err))
			}
			previousWriteTimeout = writeTimeout
		} else if previousWriteTimeout > 0 {
			// We don't want a write timeout but we previously set one, remove it.
			if err := c.SetWriteDeadline(zeroTime); err != nil {
				panic(fmt.Sprintf("BUG: error in SetWriteDeadline(zeroTime): %v", err))
			}
			previousWriteTimeout = 0
		}

		connectionClose = connectionClose ||
			(s.MaxRequestsPerConn > 0 && connRequestNum >= uint64(s.MaxRequestsPerConn)) ||
			ctx.Response.Header.ConnectionClose() ||
			(s.CloseOnShutdown && atomic.LoadInt32(&s.stop) == 1)
		if connectionClose {
			ctx.Response.Header.SetConnectionClose()
		} else if !ctx.Request.Header.IsHTTP11() {
			// Set 'Connection: keep-alive' response header for HTTP/1.0 request.
			// There is no need in setting this header for http/1.1, since in http/1.1
			// connections are keep-alive by default.
			ctx.Response.Header.setNonSpecial(strConnection, strKeepAlive)
		}

		if serverName != "" && len(ctx.Response.Header.Server()) == 0 {
			ctx.Response.Header.SetServer(serverName)
		}

		if !hijackNoResponse {
			if bw == nil {
				bw = acquireWriter(ctx)
			}
			if err = writeResponse(ctx, bw); err != nil {
				break
			}

			// Only flush the writer if we don't have another request in the pipeline.
			// This is a big of an ugly optimization for https://www.techempower.com/benchmarks/
			// This benchmark will send 16 pipelined requests. It is faster to pack as many responses
			// in a TCP packet and send it back at once than waiting for a flush every request.
			// In real world circumstances this behaviour could be argued as being wrong.
			if br == nil || br.Buffered() == 0 || connectionClose {
				err = bw.Flush()
				if err != nil {
					break
				}
			}
			if connectionClose {
				break
			}
			if s.ReduceMemoryUsage && hijackHandler == nil {
				releaseWriter(s, bw)
				bw = nil
			}
		}

		if hijackHandler != nil {
			var hjr io.Reader = c
			if br != nil {
				hjr = br
				br = nil
			}
			if bw != nil {
				err = bw.Flush()
				if err != nil {
					break
				}
				releaseWriter(s, bw)
				bw = nil
			}
			err = c.SetDeadline(zeroTime)
			if err != nil {
				break
			}
			go hijackConnHandler(ctx, hjr, c, s, hijackHandler)
			err = errHijacked
			break
		}

		if ctx.Request.bodyStream != nil {
			if rs, ok := ctx.Request.bodyStream.(*requestStream); ok {
				releaseRequestStream(rs)
			}
			ctx.Request.bodyStream = nil
		}

		s.setState(c, StateIdle)
		ctx.userValues.Reset()
		ctx.Request.Reset()
		ctx.Response.Reset()

		if atomic.LoadInt32(&s.stop) == 1 {
			err = nil
			break
		}
	}

	if br != nil {
		releaseReader(s, br)
	}
	if bw != nil {
		releaseWriter(s, bw)
	}
	if hijackHandler == nil {
		s.releaseCtx(ctx)
	}

	return
}

```

​	该函数主要对用户请求进行处理，并通过将 ctx，reader，writer 对象池化减少内存的分配与回收，从而提高程序的性能。