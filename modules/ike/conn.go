package ike

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

type Conn struct {
	// Underlying network connection
	conn net.Conn

	// Path to the probe file if not empty, otherwise no probe file
	probeFile string

	// State for handshake
	initiatorSPI [8]byte
	responderSPI [8]byte
}

func (c *Conn) String() string {
	return fmt.Sprintf("%s -> %s", c.conn.LocalAddr().String(), c.conn.RemoteAddr().String())
}

func (c *Conn) writeMessage(msg *ikeMessage) error {
	x := msg.marshal()
	if len(c.probeFile) > 0 {
		if err := ioutil.WriteFile(c.probeFile, x, 0644); err != nil {
			log.Fatalf("Error writing to probe file \"%s\": %s", c.probeFile, err.Error())
		} else {
			log.Info("Wrote probe file and exiting...")
			os.Exit(0)
		}
	}
	if len(x) > MAX_UDP_PAYLOAD_LEN {
		debug.PrintStack()
		log.Fatalf("Message exceeds max udp payload length: %s. Max: %d bytes, Need: %d bytes",
			c, MAX_UDP_PAYLOAD_LEN, len(x),
		)
	}
	n, err := c.Write(x)
	if err != nil {
		return err
	}
	if n != len(x) {
		return errors.New("unable to write message to connection")
	}
	return nil
}

// Write len(b) bytes to the connection, and return an error on failure
func (c *Conn) Write(b []byte) (written int, err error) {
	for written < len(b) {
		n, err := c.conn.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return
}

// Read an IKE message from the connection
func (c *Conn) readMessage() (msg *ikeMessage, err error) {
	raw := make([]byte, MAX_IKE_MESSAGE_LEN)

	var n int
	if n, err = c.conn.Read(raw); err != nil {
		return
	} else {
		raw = raw[:n]
	}

	msg = new(ikeMessage)
	if ok := msg.unmarshal(raw); !ok {
		err = errors.New("unable to parse ike message")
		return
	}

	return
}
