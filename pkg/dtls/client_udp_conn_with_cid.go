package dtls

import (
	"fmt"
	"net"
	"time"
)

type ClientUDPConnWithCid struct {
	udpConn *net.UDPConn
}

func (c ClientUDPConnWithCid) PromoteToCidConnection(cid []byte) error {
	// no-op for now
	fmt.Println("[ClientUDPConnWithCid::PromoteToCidConnection] TODO")
	return nil
}

func (c ClientUDPConnWithCid) Read(b []byte) (n int, err error) {
	return c.udpConn.Read(b)
}

func (c ClientUDPConnWithCid) Write(b []byte) (n int, err error) {
	return c.udpConn.Write(b)
}

func (c ClientUDPConnWithCid) Close() error {
	return c.udpConn.Close()
}

func (c ClientUDPConnWithCid) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

func (c ClientUDPConnWithCid) RemoteAddr() net.Addr {
	return c.udpConn.RemoteAddr()
}

func (c ClientUDPConnWithCid) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c ClientUDPConnWithCid) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c ClientUDPConnWithCid) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
