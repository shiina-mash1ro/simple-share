package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	stream "github.com/nknorg/encrypted-stream"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"simple-share/common"
	"strconv"
)

type ClientConfig struct {
	Address    string `json:"address"`
	Password   string `json:"password"`
	ListenPort uint16 `json:"listen_port"`
}

func main() {
	var simpleConfigPath, address, password string
	var listenPort uint16
	var usingFile bool

	if len(os.Args) > 1 {
		argFile := flag.String("file", "", "simple config path")
		argAddress := flag.String("address", "", "127.0.0.1:12345")
		argPassword := flag.String("password", "", "password")
		argListenPort := flag.Uint("listen-port", 0, "1-65535")
		argGenerateConfig := flag.Bool("gen-config", false, "")
		flag.Parse()
		if *argFile != "" {
			simpleConfigPath = *argFile
			usingFile = true
		} else {
			address = *argAddress
			password = *argPassword
			listenPort = (uint16)(*argListenPort)
			if address == "" || password == "" || listenPort == 0 {
				panic("address, password, listen-port is required")
			}
			if *argGenerateConfig {
				marshal, err := json.Marshal(ClientConfig{
					Address:    address,
					Password:   password,
					ListenPort: listenPort,
				})
				if err != nil {
					panic(err)
				}
				fmt.Println(base64.RawURLEncoding.EncodeToString(marshal))
				return
			}
		}
	} else {
		var lastFile os.FileInfo
		err := filepath.Walk(".", func(path string, info fs.FileInfo, err error) error {
			if !info.IsDir() && filepath.Ext(path) == ".txt" {
				if lastFile != nil {
					if lastFile.ModTime().Before(info.ModTime()) {
						lastFile = info
					}
				} else {
					lastFile = info
				}
			}
			return nil
		})
		if err != nil {
			panic(err.Error())
		}
		if lastFile == nil {
			panic("no config")
		}
		simpleConfigPath = lastFile.Name()
		usingFile = true
	}

	if usingFile {
		fileContent, readFileErr := ioutil.ReadFile(simpleConfigPath)
		if readFileErr != nil {
			panic(readFileErr.Error())
		}
		fileContentRaw, err := base64.RawURLEncoding.DecodeString(string(fileContent))
		if err != nil {
			panic(err.Error())
		}
		var config ClientConfig
		jsonDecodeErr := json.Unmarshal(fileContentRaw, &config)
		if jsonDecodeErr != nil {
			panic(jsonDecodeErr.Error())
		}
		address = config.Address
		password = config.Password
		listenPort = config.ListenPort
	}

	listen, err := net.Listen("tcp", ":"+strconv.Itoa(int(listenPort)))
	if err != nil {
		fmt.Printf("Listen port %d FAIL\n", listenPort)
	}
	for {
		localConn, err := listen.Accept()
		if err != nil {
			fmt.Printf("failed to accept: %s\n", err)
		}
		if localConn == nil {
			fmt.Printf("failed to accept\n")
			continue
		}
		fmt.Printf("accept conn %s\n", localConn.RemoteAddr().String())
		go func() {
			defer localConn.Close()
			remoteConn, err := net.Dial("tcp", address)
			if err != nil {
				fmt.Printf("failed to connect: %s\n", address)
				localConn.Close()
				return
			}
			defer remoteConn.Close()

			//encryptRemoteConn := common.NewEncryptStream(remoteConn, password)
			key, _ := common.GetHkdf(password, 32)
			cipher, _ := stream.NewAESGCMCipher(key)
			encryptRemoteConn, _ := stream.NewEncryptedStream(remoteConn, &stream.Config{
				Cipher:          cipher,
				SequentialNonce: true,
				MaxChunkSize:    0x3fff,
				Initiator:       true,
			})

			fmt.Printf("%s <-> :%d <-> %s <-> %s\n", localConn.RemoteAddr(), listenPort, remoteConn.LocalAddr(), address)

			if err = common.Relay(localConn, encryptRemoteConn); err != nil {
				fmt.Printf("relay error: %v\n", err)
			}
		}()
	}
}
