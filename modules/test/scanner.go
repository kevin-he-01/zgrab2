package test

import (
	"log"

	"github.com/zmap/zgrab2"
)

// Module implements the zgrab2.Module interface.
type Module struct {
}

type Scanner struct {
	config *Flags
}

type Flags struct {
	zgrab2.BaseFlags
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "My first trial at writing a ZGrab 2.0 scanner"
}

// Validate flags
func (f *Flags) Validate(args []string) (err error) {
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return "Want some help? No way dude!"
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "test"
}

// Init initializes the Scanner instance with the flags from the command
// line.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

// InitPerSender does nothing in this module.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the configured name for the Scanner.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	log.Println("Scanning for aliens on Mars...")
	var err error
	// Also OpenUDP for UDP instead of TCP
	conn, err := t.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	cn := conn
	defer func() {
		cn.Close()
	}()
	conn.Write([]byte("Hello, world! Awaiting response:\n")) // Run `nc -lvp 1337` on the scanned machine to see greeting
	buf := make([]byte, 100);
	nread, err := conn.Read(buf); // Get a response
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	buf = buf[:nread]
	// log.Println("Read", nread, "bytes: ");
	// log.Println(string(buf))
	return zgrab2.SCAN_SUCCESS, string(buf), nil
}

func RegisterModule() {
	var mod Module
	_, err := zgrab2.AddCommand("test", "A test scanner", mod.Description(), 1337, &mod)
	if err != nil {
		log.Fatal(err)
	}
}
