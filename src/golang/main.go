package main

import (
	"github.com/SpeedReach/ebpf_consensus/tcp_nodes"
	"github.com/SpeedReach/ebpf_consensus/udp_nodes"
	"time"
	"fmt"
	"net"
)

func main() {
	// Target IP address and port
	serverAddr := "192.168.33.10"
	serverPort := "7072"

	// Combine address and port
	address := net.JoinHostPort(serverAddr, serverPort)

	// Create a UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error creating connection:", err)
		return
	}
	defer conn.Close()

	// Message to send
	message := []byte("Hello, UDP!")
	
	for {
	
		// Send the message
		_, err = conn.Write(message)
		if err != nil {
			fmt.Println("Error sending message:", err)
			return
		}

		fmt.Println("Message sent!")
	}
}

func udp_start() {
	go udp_nodes.StartServer(0, 7073)
	go udp_nodes.StartServer(1, 8073)
	time.Sleep(time.Second)
	udp_nodes.StartClient()
}

func tcp_start() {
	go tcp_nodes.StartServer(0, 7073)
	go tcp_nodes.StartServer(1, 8073)
	time.Sleep(time.Second)
	tcp_nodes.StartClient()
}
