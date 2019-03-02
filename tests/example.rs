use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

use shs_core::*;

fn client(to_server: Sender<Vec<u8>>, from_server: Receiver<Vec<u8>>,
          server_pk: ServerPublicKey) {

    let net_id = NetworkId::ssb_main_network();
    let (pk, sk) = client::generate_longterm_keypair();
    let (eph_pk, eph_sk) = client::generate_eph_keypair();

    // Send client hello
    let hello = ClientHello::new(&eph_pk, &net_id);
    to_server.send(hello.to_vec()).unwrap();

    let server_eph_pk = {
        let buf = from_server.recv().unwrap();
        let server_hello = ServerHello::from_slice(&buf).unwrap();
        server_hello.verify(&net_id).unwrap()
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk).unwrap();
    let shared_b = SharedB::client_side(&eph_sk, &server_pk).unwrap();

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_id, &shared_a, &shared_b);
    to_server.send(client_auth.to_vec()).unwrap();

    // Derive shared secret
    let shared_c = SharedC::client_side(&sk, &server_eph_pk).unwrap();

    let ok = {
        let v = from_server.recv().unwrap();
        let server_acc = ServerAccept::from_buffer(v).unwrap();
        server_acc.open_and_verify(&sk, &pk, &server_pk,
                                   &net_id, &shared_a,
                                   &shared_b, &shared_c)
    };
    assert!(ok);

    // Derive shared keys for box streams
    let _c2s_key = ClientToServerKey::new(&server_pk, &net_id, &shared_a, &shared_b, &shared_c);
    let _s2c_key = ServerToClientKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c);

    let mut c2s_nonces = ClientToServerNonceGen::new(&server_eph_pk, &net_id);
    let mut s2c_nonces = ServerToClientNonceGen::new(&eph_pk, &net_id);

    let _n = c2s_nonces.next();
    let _n = s2c_nonces.next();

}

fn server(to_client: Sender<Vec<u8>>, from_client: Receiver<Vec<u8>>,
          pk: ServerPublicKey, sk: ServerSecretKey) {
    let net_id = NetworkId::ssb_main_network();
    let (eph_pk, eph_sk) = server::generate_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let buf = from_client.recv().unwrap();
        let client_hello = ClientHello::from_slice(&buf).unwrap();
        client_hello.verify(&net_id).unwrap()
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_id);
    to_client.send(hello.to_vec()).unwrap();

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk).unwrap();
    let shared_b = SharedB::server_side(&sk, &client_eph_pk).unwrap();

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let v = from_client.recv().unwrap();
        let client_auth = ClientAuth::from_buffer(v).unwrap();
        client_auth.open_and_verify(&pk, &net_id, &shared_a, &shared_b).unwrap()
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk).unwrap();

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_id, &client_sig,
                                      &shared_a, &shared_b, &shared_c);
    to_client.send(server_acc.to_vec()).unwrap();


    // Derive shared keys for box streams
    let _c2s_key = ClientToServerKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c);
    let _s2c_key = ServerToClientKey::new(&client_pk, &net_id, &shared_a, &shared_b, &shared_c);

    let mut c2s_nonces = ClientToServerNonceGen::new(&eph_pk, &net_id);
    let mut s2c_nonces = ServerToClientNonceGen::new(&client_eph_pk, &net_id);

    let _n = c2s_nonces.next();
    let _n = s2c_nonces.next();
}


#[test]
fn ok() {

    let (c2s_sender, c2s_receiver) = channel();
    let (s2c_sender, s2c_receiver) = channel();

    let (server_pk, server_sk) = server::generate_longterm_keypair();

    // The client needs to know the server's long-term pk before the handshake.
    let server_pk_copy = server_pk.clone();

    let client_thread = thread::spawn(move|| client(c2s_sender, s2c_receiver, server_pk_copy));
    let server_thread = thread::spawn(move|| server(s2c_sender, c2s_receiver, server_pk, server_sk));

    client_thread.join().unwrap();
    server_thread.join().unwrap();

}
