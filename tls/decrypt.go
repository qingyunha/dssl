package tls

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

type sBuffer struct {
	bytes.Buffer
	mu sync.Mutex

	// signal new data, len(newdata) == 1
	newdata chan struct{}
	closing chan struct{}
}

func (s *sBuffer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err = s.Buffer.Write(p)
	select {
	case s.newdata <- struct{}{}:
	case <-s.closing:
		return 0, io.ErrUnexpectedEOF
	default:
	}
	return
}

// always read n == len(p) when success
func (s *sBuffer) Read(p []byte) (n int, err error) {
	for {
		s.mu.Lock()
		if s.Len() >= len(p) {
			n, err = s.Buffer.Read(p)
			s.mu.Unlock()
			return
		}
		select {
		case <-s.newdata:
		default:
		}
		s.mu.Unlock()

		select {
		case <-s.newdata:
		case <-s.closing:
			return 0, io.EOF
		}
	}
}

func (s *sBuffer) Close() error {
	// Close can call many times
	select {
	case <-s.closing:
	default:
		close(s.closing)
	}
	return nil
}

func newsBuffer() *sBuffer {
	b := new(sBuffer)
	b.newdata = make(chan struct{}, 1)
	b.closing = make(chan struct{})
	return b
}

type GetSecretFn func([]byte) ([]byte, []byte)

type Conntrack struct {
	Addr       string
	cin, sin   *sBuffer
	chc, shc   halfConn
	cout, sout io.Writer
	suite      *cipherSuiteTLS13
	suite1     *cipherSuite
	getSecret  GetSecretFn
}

func NewConntrack(fn GetSecretFn, cout, sout io.Writer) *Conntrack {
	dec := &Conntrack{
		cin:       newsBuffer(),
		sin:       newsBuffer(),
		cout:      cout,
		sout:      sout,
		getSecret: fn,
	}
	return dec
}

func (ct *Conntrack) FeedClient(p []byte) error {
	return ct.feed(p, true)
}

func (ct *Conntrack) FeedServer(p []byte) error {
	return ct.feed(p, false)
}

func (ct *Conntrack) feed(p []byte, client bool) error {
	var err error
	if client {
		_, err = ct.cin.Write(p)
	} else {
		_, err = ct.sin.Write(p)
	}
	return err
}

func (ct *Conntrack) CloseClient() error {
	ct.cin.Close()
	return nil
}

func (ct *Conntrack) CloseServer() error {
	ct.sin.Close()
	return nil
}

func (ct *Conntrack) Close() error {
	ct.cin.Close()
	ct.sin.Close()
	return nil
}

func (ct *Conntrack) Decrypt() (err error) {
	defer func() {
		if err != nil {
			// Feed will return error after Close
			ct.Close()
		}
	}()

	// client hello
	buf := make([]byte, 1500)
	_, err = ct.cin.Read(buf[:recordHeaderLen])
	if err != nil {
		err = fmt.Errorf("clientHello: %v", err)
		return
	}
	typ := recordType(buf[0])
	if typ != recordTypeHandshake {
		err = fmt.Errorf("clientHello recordType not Handshake")
		return
	}
	// vers
	_ = uint16(buf[1])<<8 | uint16(buf[2])
	n := int(buf[3])<<8 | int(buf[4])
	if n > len(buf)-recordHeaderLen {
		err = fmt.Errorf("clienthello too large %d", n)
	}
	_, err = ct.cin.Read(buf[recordHeaderLen : recordHeaderLen+n])
	if err != nil {
		err = fmt.Errorf("client vers")
		return
	}
	var chello clientHelloMsg
	if !chello.unmarshal(buf[recordHeaderLen : recordHeaderLen+n]) {
		err = fmt.Errorf("unmarshal clientHello")
		return
	}

	// server hello
	buf = make([]byte, 1500)
	_, err = ct.sin.Read(buf[:recordHeaderLen])
	if err != nil {
		err = fmt.Errorf("serverHello %v", err)
		return
	}
	typ = recordType(buf[0])
	if typ != recordTypeHandshake {
		err = fmt.Errorf("serverHello recordType not Handshake")
		return
	}
	// vers
	_ = uint16(buf[1])<<8 | uint16(buf[2])
	n = int(buf[3])<<8 | int(buf[4])
	if n > len(buf)-recordHeaderLen {
		err = fmt.Errorf("serverHello too large %d", n)
	}
	_, err = ct.sin.Read(buf[recordHeaderLen : recordHeaderLen+n])
	if err != nil {
		err = fmt.Errorf("server vers")
		return
	}
	var shello serverHelloMsg
	if !shello.unmarshal(buf[recordHeaderLen : recordHeaderLen+n]) {
		err = fmt.Errorf("unmarshal serverHello")
		return
	}

	vers := shello.vers
	if shello.supportedVersion != 0 {
		vers = shello.supportedVersion
	}
	if vers == VersionTLS13 {
		selectedSuite := mutualCipherSuiteTLS13(chello.cipherSuites, shello.cipherSuite)
		if selectedSuite == nil {
			err = fmt.Errorf("server chose an unconfigured cipher suite")
			return
		}
		ct.suite = selectedSuite
		cSecret, sSecret := ct.getSecret(chello.random)
		if cSecret == nil || sSecret == nil {
			err = fmt.Errorf("can not get secret")
			return
		}
		ct.chc.setTrafficSecret(ct.suite, cSecret)
		ct.shc.setTrafficSecret(ct.suite, sSecret)
		ct.chc.version = vers
		ct.shc.version = vers
	} else {
		suite := mutualCipherSuite(chello.cipherSuites, shello.cipherSuite)
		if suite == nil {
			err = fmt.Errorf("server chose an unconfigured cipher suite")
			return
		}
		ct.suite1 = suite
		masterSecret, _ := ct.getSecret(chello.random)
		if masterSecret == nil {
			err = fmt.Errorf("can not get master secret")
			return
		}
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(vers, suite, masterSecret, chello.random, shello.random, suite.macLen, suite.keyLen, suite.ivLen)
		var clientCipher, serverCipher interface{}
		var clientHash, serverHash macFunction
		if suite.cipher != nil {
			clientCipher = suite.cipher(clientKey, clientIV, false /* not for reading */)
			clientHash = suite.mac(vers, clientMAC)
			serverCipher = suite.cipher(serverKey, serverIV, true /* for reading */)
			serverHash = suite.mac(vers, serverMAC)
		} else {
			clientCipher = suite.aead(clientKey, clientIV)
			serverCipher = suite.aead(serverKey, serverIV)
		}

		ct.chc.prepareCipherSpec(vers, clientCipher, clientHash)
		ct.chc.changeCipherSpec()
		ct.shc.prepareCipherSpec(vers, serverCipher, serverHash)
		ct.shc.changeCipherSpec()
		// read finish inc one
		ct.chc.incSeq()
		ct.shc.incSeq()
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	var err1, err2 error
	go func() {
		err1 = ct.decryptapp(false)
		wg.Done()
	}()
	go func() {
		err2 = ct.decryptapp(true)
		wg.Done()
	}()
	wg.Wait()

	if err1 != nil || err2 != nil {
		err = fmt.Errorf("server error:%v  client error:%v", err1, err2)
	}

	return
}

func (ct *Conntrack) decryptapp(client bool) error {
	var (
		in  *sBuffer
		out io.Writer
		hc  *halfConn
	)
	if client {
		in = ct.cin
		out = ct.cout
		hc = &ct.chc
	} else {
		in = ct.sin
		out = ct.sout
		hc = &ct.shc
	}
	defer in.Close()

	var dir string
	if client {
		dir = "-------->"
	} else {
		dir = "<--------"
	}
	hdr := []byte(fmt.Sprintf("\n%s %s %#x\n", dir, ct.Addr, hc.version))

	buf := make([]byte, 4096)
	for {
		_, err := in.Read(buf[:recordHeaderLen])
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		typ := recordType(buf[0])
		// vers
		_ = uint16(buf[1])<<8 | uint16(buf[2])
		n := int(buf[3])<<8 | int(buf[4])
		if n > maxCiphertext {
			return fmt.Errorf("exceed maxCiphertext %d", n)
		}
		if n > len(buf)-recordHeaderLen {
			b := make([]byte, n+recordHeaderLen)
			copy(b, buf[:recordHeaderLen])
			buf = b
		}
		_, err = in.Read(buf[recordHeaderLen : recordHeaderLen+n])
		if err != nil {
			return err
		}
		if typ != recordTypeApplicationData {
			continue
		}
		plaintext, t, err := hc.decrypt(buf[:recordHeaderLen+n])
		if err != nil {
			// may lose error information here
			continue
		}
		if t != recordTypeApplicationData {
			continue
		}
		out.Write(hdr)
		out.Write(plaintext)
		out.Write([]byte{'\n'})
	}
	return fmt.Errorf("decrypt application data error")
}
