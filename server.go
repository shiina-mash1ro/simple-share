package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/jech/portmap"
	stream "github.com/nknorg/encrypted-stream"
	"log"
	"net"
	"os"
	"os/signal"
	"simple-share/common"
	"strconv"
	"syscall"
)

type ServerConfig struct {
	Address    string `json:"address"`
	Password   string `json:"password"`
	ListenPort uint16 `json:"listen_port"`
}

func main() {
	var address, password string
	var listenPort uint16
	argAddress := flag.String("address", "", "127.0.0.1:12345")
	argPassword := flag.String("password", "", "password")
	argListenPort := flag.Uint("listen-port", 0, "1-65535")
	flag.Parse()

	address = *argAddress
	password = *argPassword
	listenPort = (uint16)(*argListenPort)

	if address == "" || password == "" || listenPort == 0 {
		panic("address, password, listen-port is required")
	}

	listen, err := net.Listen("tcp", ":"+strconv.Itoa(int(listenPort)))
	if err != nil {
		fmt.Printf("Listen port %d FAIL\n", listenPort)
	}

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err = portmap.Map(ctx, "share", listenPort, portmap.All, func(proto string, status portmap.Status, err error) {
			if err != nil {
				fmt.Printf("Mapping error: %v", err)
			} else if status.Lifetime > 0 {
				log.Printf("Mapped %v %v->%v for %v",
					proto,
					status.Internal, status.External,
					status.Lifetime,
				)
			} else {
				fmt.Printf("Unmapped %v %v",
					proto, status.Internal,
				)
			}
		})
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		<-terminate
		cancel()
		os.Exit(0)
	}()

	for {
		localConn, err := listen.Accept()
		if err != nil {
			fmt.Printf("failed to accept: %s\n", err)
		}
		if localConn == nil {
			fmt.Printf("failed to accept\n")
			continue
		}
		fmt.Printf("accept conn %s\n", localConn.RemoteAddr())
		go func() {
			defer localConn.Close()
			remoteConn, err := net.Dial("tcp", address)
			if err != nil {
				fmt.Printf("failed to connect: %s\n", address)
				localConn.Close()
				return
			}
			defer remoteConn.Close()
			key, _ := common.GetHkdf(password, 32)
			cipher, _ := stream.NewAESGCMCipher(key)
			encryptLocalConn, _ := stream.NewEncryptedStream(localConn, &stream.Config{
				Cipher:          cipher,
				SequentialNonce: true,
				MaxChunkSize:    0x3fff,
				//Initiator:       true,
			})
			//encryptLocalConn := common.NewEncryptStream(localConn, password)

			fmt.Printf("%s <-> :%d <-> %s\n", encryptLocalConn.RemoteAddr(), listenPort, remoteConn.RemoteAddr())

			if err = common.Relay(remoteConn, encryptLocalConn); err != nil {
				fmt.Printf("relay error: %v\n", err)
			}
		}()
	}

}
