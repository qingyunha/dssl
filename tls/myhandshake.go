package tls

import (
	"bytes"
	"errors"
	"sync/atomic"
)

/*
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
*/

func (c *Conn) ClientHandshake13(bclient, bserver, finisheded,
	clientHandshake, serverHandshake, clientTraffic, serverTraffic []byte) (err error) {
	var hello = new(clientHelloMsg)
	var serverHello = new(serverHelloMsg)

	if !hello.unmarshal(bclient) {
		return errors.New("client unmarshal")
	}
	if !serverHello.unmarshal(bserver) {
		return errors.New("server unmarshal")
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	if c.vers == VersionTLS13 {
		hs := &clientHandshakeStateTLS13{
			c:           c,
			serverHello: serverHello,
			hello:       hello,
			ecdheParams: nil, // TODO
			session:     nil,
			earlySecret: nil,
			binderKey:   nil,
		}

		return hs.handshake13(clientHandshake, serverHandshake, clientTraffic, serverTraffic)
	}

	return errors.New("unknown vers")
}

func (hs *clientHandshakeStateTLS13) handshake13(clientHandshake, serverHandshake, clientTraffic, serverTraffic []byte) error {
	c := hs.c
	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}
	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		return errors.New("processHelloRetryRequest")
	}

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}

	c.out.setTrafficSecret(hs.suite, clientHandshake)
	c.in.setTrafficSecret(hs.suite, serverHandshake)
	hs.trafficSecret = clientTraffic
	c.in.setTrafficSecret(hs.suite, serverTraffic)
	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (c *Conn) serverHandshake13(bclient, bserver, finisheded,
	clientHandshake, serverHandshake, clientTraffic, serverTraffic []byte) (err error) {

	c.config.serverInit(nil)

	var clientHello = new(clientHelloMsg)
	var serverHello = new(serverHelloMsg)

	if !clientHello.unmarshal(bclient) {
		return errors.New("client unmarshal")
	}
	if !serverHello.unmarshal(bserver) {
		return errors.New("server unmarshal")
	}

	hs := serverHandshakeStateTLS13{
		c:           c,
		clientHello: clientHello,
	}
	return hs.handshake13(clientHandshake, serverHandshake, clientTraffic, serverTraffic)

}

func (hs *serverHandshakeStateTLS13) handshake13(clientHandshake, serverHandshake, clientTraffic, serverTraffic []byte) error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	c.cipherSuite = hs.suite.id

	c.buffering = true
	c.in.setTrafficSecret(hs.suite, clientHandshake)
	c.out.setTrafficSecret(hs.suite, serverHandshake)
	hs.trafficSecret = clientTraffic
	c.out.setTrafficSecret(hs.suite, serverTraffic)
	c.in.setTrafficSecret(hs.suite, hs.trafficSecret)

	return nil
}
