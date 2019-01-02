package udp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const receiveMTU = 8192

var (
	errClosedListener          = errors.New("udp: listener closed")
	errRecordTooShort          = errors.New("udp: DTLS record too short to carry a CID")
	errUnknownCid              = errors.New("udp: DTLS record carries a CID that is not registered")
	errNoListenerForConnection = errors.New("udp: no listener associated with connection")
)

// Listener augments a connection-oriented Listener over a UDP PacketConn
type Listener struct {
	pConn *net.UDPConn

	lock      sync.RWMutex
	accepting bool
	acceptCh  chan *Conn
	doneCh    chan struct{}
	doneOnce  sync.Once
	cidLen    int

	conns    map[string]*Conn // maps receiver's 2-tuple into Conn
	cidConns map[string]*Conn // maps CIDs into Conn
}

// SetCidLen sets the size in bytes of the connection id used when
// receiving
func (l *Listener) SetCidLen(v int) {
	l.cidLen = v
}

func (l *Listener) MoveConnToCidConns(conn *Conn, cid []byte) {
	// TODO(tho) delete conn from conns map
	l.cidConns[string(cid)] = conn
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil

	case <-l.doneCh:
		return nil, errClosedListener
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	var err error
	l.doneOnce.Do(func() {
		l.accepting = false
		close(l.doneCh)
		err = l.cleanup()
	})

	return err
}

// cleanup closes the packet conn if it is no longer used
// The caller should hold the read lock.
func (l *Listener) cleanup() error {
	if !l.accepting && len(l.conns) == 0 {
		return l.pConn.Close()
	}
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

// Listen creates a new listener
func Listen(network string, laddr *net.UDPAddr) (*Listener, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		pConn:     conn,
		acceptCh:  make(chan *Conn),
		conns:     make(map[string]*Conn),
		cidConns:  make(map[string]*Conn),
		accepting: true,
		doneCh:    make(chan struct{}),
	}

	go l.readLoop()

	return l, nil
}

// maybeExtractCid tries to grab the CID from the records header
func (l Listener) maybeExtractCid(pkt []byte) ([]byte, error) {
	if pkt[0] == 0x19 {
		if len(pkt[11:]) < l.cidLen+2 {
			return nil, errRecordTooShort
		}

		cid := make([]byte, l.cidLen)
		copy(cid, pkt[11:11+l.cidLen])

		fmt.Printf("[Listener::maybeExtractCid] got cid % x\n", cid)

		return cid, nil
	}

	return nil, nil
}

// readLoop has to tasks:
// 1. Dispatching incoming packets to the correct Conn.
//    It can therefore not be ended until all Conns are closed.
// 2. Creating a new Conn when receiving from a new remote.
func (l *Listener) readLoop() {
	buf := make([]byte, receiveMTU)

readLoop:
	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if err != nil {
			return
		}

		// peek at the header to see if the record carries a CID
		cid, err := l.maybeExtractCid(buf)
		if err != nil {
			continue
		}

		conn, err := l.getConn(raddr, cid)
		if err != nil {
			continue
		}
		select {
		case cBuf := <-conn.readCh:
			n = copy(cBuf, buf[:n])
			conn.sizeCh <- n
		case <-conn.doneCh:
			continue readLoop
		}
	}
}

// TODO "promote connection": l.cidConns[string(cid)] = conn

func (l *Listener) getConn(raddr net.Addr, cid []byte) (*Conn, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	var ok bool
	var conn *Conn

	if cid != nil {
		conn, ok = l.cidConns[string(cid)]
		// a connection with cid is not created ex-nihil on arrival of
		// its first packet.  instead it's an existing connection that
		// is "promoted" by the higher layer that owns it when a cid
		// has been successfully negotiated during DTLS handshake.
		// therefore, a record bearing a cid that can't be found among
		// the currently registered cid-enabled connections is
		// something that must be dropped here and now -- it's the
		// analogous of a "connected" UDP socket receiving a datagram
		// on an unknown 4-tuple.
		if !ok {
			return nil, errUnknownCid
		}
		// force update the peer's 2-tuple (in case it changed because
		// of NAT rebind or connection migration)
		conn.SetRemoteAddr(raddr)
	} else {
		conn, ok = l.conns[raddr.String()]
		if !ok {
			if !l.accepting {
				return nil, errClosedListener
			}
			conn = l.newConn(raddr, cid)
			l.conns[raddr.String()] = conn
			l.acceptCh <- conn
		}
	}

	return conn, nil
}

// Conn augments a connection-oriented connection over a UDP PacketConn
type Conn struct {
	listener *Listener

	rAddr net.Addr
	cid   []byte

	readCh chan []byte
	sizeCh chan int

	lock     sync.RWMutex
	doneCh   chan struct{}
	doneOnce sync.Once
}

func (l *Listener) newConn(rAddr net.Addr, cid []byte) *Conn {
	return &Conn{
		listener: l,
		rAddr:    rAddr,
		cid:      cid,
		readCh:   make(chan []byte),
		sizeCh:   make(chan int),
		doneCh:   make(chan struct{}),
	}
}

// Read
func (c *Conn) Read(p []byte) (int, error) {
	select {
	case c.readCh <- p:
		n := <-c.sizeCh
		return n, nil
	case <-c.doneCh:
		return 0, io.EOF
	}
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	c.lock.Lock()
	l := c.listener
	c.lock.Unlock()

	if l == nil {
		return 0, io.EOF
	}

	return l.pConn.WriteTo(p, c.rAddr)
}

// Close closes the conn and releases any Read calls
func (c *Conn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	var err error
	c.doneOnce.Do(func() {
		close(c.doneCh)
		c.listener.lock.Lock()
		delete(c.listener.conns, c.rAddr.String())
		err = c.listener.cleanup()
		c.listener.lock.Unlock()
		c.listener = nil
	})

	return err
}

// LocalAddr is a stub
func (c *Conn) LocalAddr() net.Addr {
	c.lock.Lock()
	l := c.listener
	c.lock.Unlock()

	if l == nil {
		return nil
	}

	return l.pConn.LocalAddr()
}

// RemoteAddr is a stub
func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
}

// SetRemoteAddr updates the remote address associated with this Conn
func (c *Conn) SetRemoteAddr(v net.Addr) {
	c.rAddr = v
}

// SetDeadline is a stub
func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a stub
func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a stub
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *Conn) PromoteToCidConnection(cid []byte) error {
	c.lock.Lock()
	l := c.listener
	c.lock.Unlock()

	if l == nil {
		return errNoListenerForConnection
	}

	l.MoveConnToCidConns(c, cid)

	return nil

}
