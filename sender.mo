import Receiver "canister:receiver";

import AES128 "encryption_modules/aes128";
import DiffieHellman "encryption_modules/diffiehellman";
import Converter "encryption_modules/converter";

import Debug "mo:base/Debug";
import Stack "mo:base/Stack";
import List "mo:base/List";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Text "mo:base/Text";
import Principal "mo:base/Principal";

actor Sender {

	
	// This function does the following:
	// (1) It initiates the Diffie-Hellman key exchange process by choosing a private key, prime, generator
	// (2) It sends along the Diffie-Hellman prime, generator and private key to the Receiver canister
	// (3) It obtains the Receiver canister's public key, and uses it to compute the Diffie-Hellman secret key
	// (4) It converts the Diffie-Hellman secret key to a secret AES key
	// (5) It converts the message to hex, and encrypts the message using AES.encrypt_hex (using this secret key)
	// (6) It sends the encrypted message across
	
	public func send_secure_message(message : Text) : async () {

		let p : Nat = DiffieHellman.rfc_prime();
		let g : Nat = DiffieHellman.default_generator();
		let a : Nat = await DiffieHellman.get_random_number(p);
		let ga : Nat = DiffieHellman.pow_p(g,a,p);
		let gb : Nat = await Receiver.receive_diffiehellman_data(g,p,ga);
		let secret_key = DiffieHellman.pow_p(gb,a,p);
		let AES_key : Text = Converter.nat8_to_doublehex(DiffieHellman.DH_to_AES_key(secret_key)); //this is a hex key
		
		Debug.print("Sender: I have independently computed the AES secret key, and it is " # AES_key);
		
		let hex_message : Text = Converter.unicode_to_doublehex(message);
		
		Debug.print("Sender: The raw hex data (before encryption) is " # hex_message);

		let encrypted_message : Text = AES128.encrypt_hex(hex_message, AES_key, "0");

		Debug.print("Sender: The encrypted message we are sending to the Receiver is " # encrypted_message);
		
		Receiver.insert_encrypted_message(encrypted_message);
	};
			
};