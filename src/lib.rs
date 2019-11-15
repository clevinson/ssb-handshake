//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

#[macro_use]
extern crate quick_error;
extern crate ssb_crypto;

use ssb_crypto::{handshake::HandshakeKeys, NetworkKey, NonceGen, PublicKey, SecretKey};

use core::mem::size_of;
use std::io::{self, Read, Write, ErrorKind};

mod error;
mod utils;
pub use error::HandshakeError;
pub mod crypto;
use crypto::{
    gen_client_eph_keypair, gen_server_eph_keypair,
    message::{ClientAuth, ClientHello, ServerAccept, ServerHello},
    outcome::client_side_handshake_keys,
    outcome::server_side_handshake_keys,
    shared_secret::{SharedA, SharedB, SharedC},
    ClientEphPublicKey, ClientPublicKey, ClientSecretKey, ServerEphPublicKey, ServerPublicKey,
    ServerSecretKey,
};

// TODO: memzero our secrets, if sodiumoxide doesn't do it for us.

/// Perform the client side of the handshake using the given `Read + Write` stream.
pub fn client<S>(
    mut stream: S,
    net_key: NetworkKey,
    pk: PublicKey,
    sk: SecretKey,
    server_pk: PublicKey,
) -> Result<HandshakeKeys, HandshakeError>
where
    S: Read + Write,
{
    let pk = ClientPublicKey(pk);
    let sk = ClientSecretKey(sk);
    let server_pk = ServerPublicKey(server_pk);

    let (eph_pk, eph_sk) = gen_client_eph_keypair();
    let hello = ClientHello::new(&eph_pk, &net_key);
    stream.write_all(&hello.as_slice())?;
    stream.flush()?;

    let server_eph_pk = {
        let mut buf = [0u8; size_of::<ServerHello>()];
        let size = stream.read(&mut buf)?;

        if size == 0 {
            // server verify failed
            let eof = io::Error::from(ErrorKind::UnexpectedEof);
            return Err(HandshakeError::Io(eof));
        }

        let server_hello = ServerHello::from_slice(&buf)?;
        server_hello.verify(&net_key)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk)?;
    let shared_c = SharedC::client_side(&sk, &server_eph_pk)?;

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_key, &shared_a, &shared_b);
    stream.write_all(client_auth.as_slice())?;
    stream.flush()?;

    let mut buf = [0u8; 80];
    stream.read_exact(&mut buf)?;

    let server_acc = ServerAccept::from_buffer(buf.to_vec())?;
    let v = server_acc.open_and_verify(
        &sk, &pk, &server_pk, &net_key, &shared_a, &shared_b, &shared_c,
    )?;

    Ok(client_side_handshake_keys(
        v,
        &pk,
        &server_pk,
        &eph_pk,
        &server_eph_pk,
        &net_key,
        &shared_a,
        &shared_b,
        &shared_c,
    ))
}

/// Perform the server side of the handshake using the given `Read + Write` stream.
pub fn server<S>(
    mut stream: S,
    net_key: NetworkKey,
    pk: PublicKey,
    sk: SecretKey,
) -> Result<HandshakeKeys, HandshakeError>
where
    S: Read + Write
{
    let pk = ServerPublicKey(pk);
    let sk = ServerSecretKey(sk);

    let (eph_pk, eph_sk) = gen_server_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0u8; 64];
        stream.read_exact(&mut buf)?;
        let client_hello = ClientHello::from_slice(&buf)?;
        client_hello.verify(&net_key)?
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_key);
    stream.write_all(hello.as_slice())?;
    stream.flush()?;

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk)?;
    let shared_b = SharedB::server_side(&sk, &client_eph_pk)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        stream.read_exact(&mut buf)?;

        let client_auth = ClientAuth::from_buffer(buf.to_vec())?;
        client_auth.open_and_verify(&pk, &net_key, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    let server_acc = ServerAccept::new(
        &sk,
        &client_pk,
        &net_key,
        &client_sig,
        &shared_a,
        &shared_b,
        &shared_c,
    );
    stream.write_all(server_acc.as_slice())?;
    stream.flush()?;

    Ok(server_side_handshake_keys(
        &pk,
        &client_pk,
        &eph_pk,
        &client_eph_pk,
        &net_key,
        &shared_a,
        &shared_b,
        &shared_c,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb::{RbConsumer, RbProducer, RB, SpscRb, Producer, Consumer};
    use std::io::{self, ErrorKind};
    use std::{
        thread,
        sync::{Arc, RwLock},
    };

    use ssb_crypto::{generate_longterm_keypair, NetworkKey, PublicKey};

    struct Connection {
        closed: Arc<RwLock<bool>>,
        s2c: SpscRb<u8>,
        c2s: SpscRb<u8>,
    }

    struct Stream {
        closed: Arc<RwLock<bool>>,
        writer: Producer<u8>,
        reader: Consumer<u8>,
    }

    impl Connection {
        fn new() -> Self {
            Self {
                closed: Arc::new(RwLock::new(false)),
                s2c: SpscRb::new(1024),
                c2s: SpscRb::new(1024),
            }
        }

        fn server(&self) -> Stream {
            Stream {
                closed: self.closed.clone(),
                writer: self.s2c.producer(),
                reader: self.c2s.consumer(),
            }
        }

        fn client(&self) -> Stream {
            Stream {
                closed: self.closed.clone(),
                writer: self.c2s.producer(),
                reader: self.s2c.consumer(),
            }
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            let mut closed = self.closed.write().unwrap();
            *closed = true;
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
            let n = buf.len();
            let mut count = 0;
            let mut closed = {
                *self.closed.read().unwrap()
            };

            while count < n && !closed {
                match self.reader.read(&mut buf[count..]) {
                    Ok(size) => { count += size },
                    Err(_) => {}
                }

                closed = {
                    *self.closed.read().unwrap()
                };
            }

            Ok(count)
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            match self.writer.write_blocking(buf) {
                Some(size) => Ok(size),
                None => Ok(0),
            }
        }

        fn flush(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    #[test]
    fn basic() {
        let connection = Connection::new();
        let (mut c_stream, mut s_stream) = (connection.client(), connection.server());

        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let net_key = NetworkKey::SSB_MAIN_NET;

        let c_thread_net_key = net_key.clone();
        let c_thread_s_pk = s_pk.clone();
        let c_thread = thread::spawn(move || {
            client(&mut c_stream, c_thread_net_key, c_pk, c_sk, c_thread_s_pk)
        });

        let s_thread_net_key = net_key.clone();
        let s_thread = thread::spawn(move || {
            server(&mut s_stream, s_thread_net_key, s_pk, s_sk)
        });

        let mut c_out = c_thread.join().unwrap().unwrap();
        let mut s_out = s_thread.join().unwrap().unwrap();

        assert_eq!(c_out.write_key, s_out.read_key);
        assert_eq!(c_out.read_key, s_out.write_key);

        assert_eq!(c_out.write_noncegen.next(), s_out.read_noncegen.next());
        assert_eq!(c_out.read_noncegen.next(), s_out.write_noncegen.next());
    }

    fn is_eof_err<T>(r: &Result<T, HandshakeError>) -> bool {
        match r {
            Err(HandshakeError::Io(e)) => e.kind() == ErrorKind::UnexpectedEof,
            _ => false,
        }
    }

    #[test]
    fn server_rejects_wrong_netkey() {
        let connection = Connection::new();
        let (mut c_stream, mut s_stream) = (connection.client(), connection.server());

        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let c_thread_s_pk = s_pk.clone();
        let c_thread = thread::spawn(move || {
            let net_key = NetworkKey::random();
            client(&mut c_stream, net_key, c_pk, c_sk, c_thread_s_pk)
        });

        let s_thread = thread::spawn(move || {
            let net_key = NetworkKey::random();
            server(&mut s_stream, net_key, s_pk, s_sk)
        });

        let c_out = c_thread.join().unwrap();
        assert!(is_eof_err(&c_out));

        let s_out = s_thread.join().unwrap();
        match s_out {
            Ok(_) => assert!(false, "expected HandshakeError::ClientHelloVerifyFailed, got result"),
            Err(HandshakeError::ClientHelloVerifyFailed) => assert!(true),
            Err(e) => assert!(false, "expected HandshakeError::ClientHelloVerifyFailed, got other error: {:?}", e),
        }
    }

    #[test]
    fn server_rejects_wrong_pk() {
        test_handshake_with_bad_server_pk(
            PublicKey::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
                .unwrap(),
        );

        let (pk, _sk) = generate_longterm_keypair();
        test_handshake_with_bad_server_pk(pk);
    }

    fn test_handshake_with_bad_server_pk(bad_pk: PublicKey) {
        let connection = Connection::new();
        let (mut c_stream, mut s_stream) = (connection.client(), connection.server());

        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let net_key = NetworkKey::SSB_MAIN_NET;

        let c_thread_net_key = net_key.clone();
        let c_thread = thread::spawn(move || {
            client(&mut c_stream, c_thread_net_key, c_pk, c_sk, bad_pk)
        });

        let s_thread_net_key = net_key.clone();
        let s_thread = thread::spawn(move || {
            server(&mut s_stream, s_thread_net_key, s_pk, s_sk)
        });

        let c_out = c_thread.join().unwrap();
        let s_out = s_thread.join().unwrap();

        assert!(c_out.is_err());
        assert!(s_out.is_err());
    }

}
