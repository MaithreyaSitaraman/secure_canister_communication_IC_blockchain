/**
 * Module      : diffiehellman.mo
 * Description : Helper functions to perform the Diffie Hellman Key Exchange
 * Copyright   : Cramium Inc.
 * Creator   : Maithreya Sitaraman
 * License  : Creative Commons
 */

import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Debug "mo:base/Debug";
import Random "mo:base/Random";

module {

	// The prime and generator below is considered secure, and is an expert-recommended choice. 
	// If a prime is such that (p-1)/2 is highly factorizable, then this is a bad choice for a prime since Diffie-Hellman can be broken via CRT
	// On the other hand, if a prime is such that (p-1)/2, it is an ideal choice for a prime
	let the_rfc_prime : Nat = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559;
	let the_default_generator : Nat = 2;

	let SubnetManager : actor {
	raw_rand() : async Blob;
	} = actor "aaaaa-aa";

	public func rfc_prime() : Nat {
		return the_rfc_prime;
	};

	public func default_generator() : Nat {
		return the_default_generator;
	};

	// Takes powers in logarithmic time
	public func pow(g : Nat, a : Nat) : Nat {
		if (a % 2 == 0){
			let a_2 : Nat = a/2;
			let s : Nat = pow(g,a_2);
			return s*s;
		}
		else if (a == 1){
			return g;
		}
		else {
			let a_2 : Nat = (a-1)/2;
			let s : Nat = pow(g,a_2);
			return g*s*s;
		};
		return 0;
	};

	// Takes powers modulo p in logarithmic time
	public func pow_p(g : Nat, a : Nat, p : Nat) : Nat {
		
		if(a == 0){
			return 1;
		};
		
		if (a % 2 == 0){
			let a_2 : Nat = a/2;
			let s : Nat = pow_p(g,a_2,p);
			return s*s % p;
		}
		else if (a == 1){
			return g % p;
		}
		else {
			let a_2 : Nat = (a-1)/2;
			let s : Nat = pow_p(g,a_2,p);
			return g*s*s % p;
		};
		return 0;
	};

	// generates large enough random numbers to be used as Diffie-Hellman private keys
	public func get_random_number (p : Nat) : async Nat {
		let seed1 = await SubnetManager.raw_rand();
		let seed2 = await SubnetManager.raw_rand();
	
		let rand_1 = Random.Finite(seed1);
		let rand_2 = Random.Finite(seed2);
	
		let r1_q : ?Nat = rand_1.range(255);
		let r2_q : ?Nat = rand_2.range(255);
	
		var r1 : Nat = 20;
		var r2 : Nat = 23;
	
		switch(r1_q) {
		case (null) {r1 := r1};
		case(?r1_q) {r1 := r1_q};
		};

		switch(r2_q) {
		case (null) {r2 := r2};
		case(?r2_q) {r2 := r2_q};
		};
			
		return (r1*r2+r1+r2) % p;
	};

	// helper function, character to Nat
	func char_to_nat (c : Char) : Nat {
		if(c == '0'){
			return 0;
		}
		else if(c == '1'){
			return 1;
		}
		else if(c == '2'){
			return 2;
		}
		else if(c == '3'){
			return 3;
		}
		else if(c == '4'){
			return 4;
		}
		else if(c == '5'){
			return 5;
		}
		else if(c == '6'){
			return 6;
		}
		else if(c == '7'){
			return 7;
		}
		else if(c == '8'){
			return 8;
		}
		else if(c == '9'){
			return 9;
		};
		return 0;	
	};
	
	// converts a Diffie-Hellman secret key to an AES key
	public func DH_to_AES_key(n : Nat) : [Nat8] {

		var key : [var Nat] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];	
		
		var counter : Nat = 0;
		
		for (c in Nat.toText(n).chars()){
			let m : Nat = char_to_nat(c);
			key[counter % 16] := (key[counter % 16]+m*m+4*m+1) % 256; //i added some irreducible quadratic over Z which doesnt suffer from parity issues
			counter := counter +1;
		};
		
		return [Nat8.fromNat(key[0]), Nat8.fromNat(key[1]), Nat8.fromNat(key[2]), Nat8.fromNat(key[3]), Nat8.fromNat(key[4]), Nat8.fromNat(key[5]), Nat8.fromNat(key[6]), Nat8.fromNat(key[7]), Nat8.fromNat(key[8]), Nat8.fromNat(key[9]), Nat8.fromNat(key[10]), Nat8.fromNat(key[11]), Nat8.fromNat(key[12]), Nat8.fromNat(key[13]), Nat8.fromNat(key[14]), Nat8.fromNat(key[15])];
	};

};
