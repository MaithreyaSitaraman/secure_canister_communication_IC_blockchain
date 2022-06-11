import AES128 "encryption_modules/aes128";
import DiffieHellman "encryption_modules/diffiehellman";
import Converter "encryption_modules/converter";
import PolynomialHandling "encryption_modules/polynomial_handling";

import HashMap "mo:base/HashMap";
import Debug "mo:base/Debug";
import List "mo:base/List";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Nat8 "mo:base/Nat8";

actor Receiver {

	// Hashmap of caller principal ID -> temporary AES secret key (hex). 
	// Key is zeroed after first use or after timeout, to prevent a future hardware breach from compromising past data.
	// Data stored in a hashmap for scalability, i.e Encrypted messages can be received from multiple Principal IDs and the canister can handle all of them
	let secretkeys_temp_db = HashMap.HashMap<Principal, Text>(1, Principal.equal, Principal.hash); 
	
	
	//Just for demonstration purposes, we store the most recent decrypted message in a variable which we can later read
	// (to verify the message has been decrypted correctly)	
	var decrypted_received_message = "";
	
	// We need the switch_get since we need to produce Text and not ?Text.
	//Otherwise, we cannot pass into functions (from encryption modules) that take Text as input
	func switch_get_key(k : Principal) : Text {
		let item : ?Text = secretkeys_temp_db.get(k);
		var switched : Text = "0";
		switch(item) {
		case (null) {switched := switched};
		case(?item) {switched := item};
		};
		return switched;	
	};
	
	// This function receives the data from Diffie-Hellman key exchange
	// It then sends a private key back to the sender, and computes the Diffie-Hellman secret key 
	// It converts the Diffie-Hellman secret key to a secret AES key and stores this in the hashmap "secretkeys_temp_db"
	public shared (msg) func receive_diffiehellman_data (g : Nat, p : Nat, ga : Nat) : async Nat {		
		let b : Nat = await DiffieHellman.get_random_number(p);
		let secret_key : Nat = DiffieHellman.pow_p(ga,b,p);
		let AES_key : Text = Converter.nat8_to_doublehex(DiffieHellman.DH_to_AES_key(secret_key));	

		Debug.print("Receiver: I have independently computed the AES secret key, and it is " # AES_key);

		secretkeys_temp_db.put(msg.caller, AES_key);
	
		return DiffieHellman.pow_p(g,b,p);
	};

	// This function uses the AES-secret key to decrypt the encrypted data it receives
	// It looks up the correct key by Principal ID in the hashmap "secretkeys_temp_db"
	// Lastly, it deletes the key from "secretkeys_temp_db" to protect current data against future hardware breaches.
	public shared (msg) func insert_encrypted_message (encrypted_message : Text) {
	
		Debug.print("Receiver: The encrypted message I have received is " # encrypted_message);

		let AESkey : Text = switch_get_key(msg.caller); //this is a hex key
				
		secretkeys_temp_db.delete(msg.caller); //not storing keys beyond needed since this could compromise the exchanged data in the event of a hardware breach
	
		let decrypted_message_hex : Text = AES128.decrypt_hex(encrypted_message, AESkey, "0");
		
		decrypted_received_message := Converter.nat8_to_string(Converter.hex_to_nat8(decrypted_message_hex));

		Debug.print("Receiver: The decrypted message using my AES secret key is: " # decrypted_received_message);

	};
	
	// A query function to verify that the message has been correctly decrypted
	// (Just for demonstration purposes)
	public query func view_decrypted_received_message() : async Text{
		return decrypted_received_message;
	};
	
};