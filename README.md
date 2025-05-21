## STCP

#### Overview

This is a project with implementation of a TCP-style transport layer protocol. To extend to the basic design of TCP, we allows the receiver to buffer all the possible information in the receiver window. This allow the reusability of the information, which makes the transportation faster. 



#### Implementation detail

I use the similar structure for the TCP communication as my STCP, the transport layer regular check the signal from Application Layer and Network Layer for new information need to be processed. I maintained the sender window and receiver window on the two sides. With sender window checking the information sent and the current sender buffer size, the receiver window maintaining a boolean checking array for tracking the bytes received. When we receive the bytes at the beginning of the window, we move our whole buffer so as the window.



#### Author

Hansong Sun **(with the implementation of `transport.c`)**



#### Building

You can use make to build the whole project.

```
make
```



#### Testing

The sample `server.c` and `client.c` in the folder are created for you to test on the project. By running building command, you will get the executables `server` and `client`. 

**Server**: You can run `./server` to run the server. If you want unstable network, use `./server -U` instead.

**Client**: 

- Interaction mode: `./client [-U] (ip:port)`(For local test, please enter `localhost:port`). When the initialization are setup, you can enter the file name you want to transfer in the terminal. Then the file will transfer from the server to the client to a file called `rcvd`. 
- Single-file transfer mode: `./client [-U] -f (filename) (ip:port)`. The mode are designed for single file transfer, it is similar to the mode above, but this allows you to test the termination of TCP (Send/Receive fin pack).



#### Update log

- 2025/5/20 - The version `1.0` complete. In this version, STCP still use the constant Timeout.