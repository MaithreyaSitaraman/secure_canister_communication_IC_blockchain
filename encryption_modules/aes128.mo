/**
 * Module      : aes128.mo
 * Description : Implementation of the Symmetric encryption algorithm AES128
 * Copyright   : Cramium Inc.
 * Creator   : Maithreya Sitaraman
 * License  : Creative Commons
 */

import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import List "mo:base/List";
import Debug "mo:base/Debug";

import Converter "./converter";
import Padding "./padding";
import PolyHandling "./polynomial_handling";

module {

	let s_box : [Nat8] = [
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ];
    
	let inv_s_box : [Nat8] = [
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
	];

	let round_constants : [Nat8] = [
		0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	];
	
	//******************	
	//testing functions (ignore these)
	//******************	
	
	public func print_sbox() : [Nat8] {
		return s_box;
	};

	public func print_sbox_entry(i : Nat) : Nat8 {
		return s_box[i];
	};
	
	public func print_rcons () : [Nat8]{
		return round_constants;
	}; 
	
	public func print_round_constants(){
		for(c in Iter.fromArray(round_constants)){
			//Debug.print(Nat.toText(Nat8.toNat(c)));
		};	
	};
				
	func transpose (M : [[Nat8]]) : [[Nat8]]{
		return [[M[0][0], M[1][0], M[2][0], M[3][0]], [M[0][1], M[1][1], M[2][1], M[3][1]], [M[0][2], M[1][2], M[2][2], M[3][2]], [M[0][3], M[1][3], M[2][3], M[3][3]]]
	};
	
	//******************	
	//helper functions 
	//******************	
		
		
	//rearranges array into matrix
	func array_to_matrix(a : [Nat8]) : [[Nat8]]{
		let output : [[Nat8]] = [[a[0], a[4], a[8], a[12]], [a[1], a[5], a[9], a[13]], [a[2], a[6], a[10], a[14]], [a[3], a[7], a[11], a[15]]];
		return output;
	};

	//rearranges matrix into array
	func matrix_to_array(M : [[Nat8]]) : [Nat8]{
		let output : [Nat8] = [M[0][0], M[1][0], M[2][0], M[3][0], M[0][1], M[1][1], M[2][1], M[3][1], M[0][2], M[1][2], M[2][2], M[3][2], M[0][3], M[1][3], M[2][3], M[3][3]];
		return output;
	};

	//adds four binary numbers
	func sum4 (x1 : [Nat8], x2 : [Nat8], x3 : [Nat8], x4 : [Nat8]) : [Nat8]{
		var output_list : List.List<Nat8> = List.nil<Nat8>();
		for(i in Iter.range(0,x1.size()-1)){
			output_list := List.reverse(output_list);
			output_list := List.push((x1[i]+x2[i]+x3[i]+x4[i]) % 2, output_list);
			output_list := List.reverse(output_list);
		};
		
		return List.toArray(output_list);
	};

	//******************	
	//vector operations 
	//******************	
		
	// inner product of two vectors with binary entries (with field operations)
	func inner(v1 : [[Nat8]], v2 : [[Nat8]]) : [Nat8]{
		return sum4(PolyHandling.mult_for_aes128(v1[0], v2[0]), PolyHandling.mult_for_aes128(v1[1], v2[1]), PolyHandling.mult_for_aes128(v1[2], v2[2]), PolyHandling.mult_for_aes128(v1[3], v2[3]))
	};

	// xor addition operation -- takes in Nat8, not binary. converts to binary, performs the xor, and converts back.
	public func xor (w1: [Nat8], w2 : [Nat8]) : [Nat8]{
		let w1_bin : [[Nat8]] = Converter.nat8_to_doublebinary(w1);
		let w2_bin : [[Nat8]] = Converter.nat8_to_doublebinary(w2);
		
		var output_list : List.List<Nat8> = List.nil<Nat8>();
		
		for(i in Iter.range(0,w1_bin.size()- 1)){
			var sublist : List.List<Nat8> = List.nil<Nat8>();
			for(j in Iter.range(0, 7)){
				sublist := List.reverse(sublist);
				sublist := List.push((w1_bin[i][j]+w2_bin[i][j]) % 2, sublist);
				sublist := List.reverse(sublist);
			};
			let value : Nat8 = Converter.binary_to_nat8(List.toArray(sublist));
						
			output_list := List.reverse(output_list);
			output_list := List.push(value, output_list);
			output_list := List.reverse(output_list);			
		};
		
		return List.toArray(output_list);
		
	};
	
	// mixes a single column step (using the AES mix-column matrix)
	public func mix_single_column(v : [Nat8]) : [Nat8]{
		let one : [Nat8] = [0,0,0,0,0,0,0,1];
		let two : [Nat8] = [0,0,0,0,0,0,1,0];
		let three : [Nat8] = [0,0,0,0,0,0,1,1];
		
		let v_bin : [[Nat8]] = [Converter.n_to_binary(v[0]), Converter.n_to_binary(v[1]), Converter.n_to_binary(v[2]), Converter.n_to_binary(v[3])];
		let M : [[[Nat8]]] = [[two, three, one, one], [one, two, three, one], [one, one, two, three], [three, one, one, two]];
		
		return [Converter.binary_to_nat8(inner(M[0], v_bin)), Converter.binary_to_nat8(inner(M[1], v_bin)), Converter.binary_to_nat8(inner(M[2], v_bin)), Converter.binary_to_nat8(inner(M[3], v_bin))];
	};

	// inverse-mixes a single column step (using the inverse AES mix-column matrix)	
	public func inverse_mix_single_column(v : [Nat8]) : [Nat8]{
		let fourteen : [Nat8] = Converter.n_to_binary(Nat8.fromNat(14));
		let eleven : [Nat8] = Converter.n_to_binary(Nat8.fromNat(11));
		let thirteen : [Nat8] = Converter.n_to_binary(Nat8.fromNat(13));
		let nine : [Nat8] = Converter.n_to_binary(Nat8.fromNat(9));
				
		let v_bin : [[Nat8]] = [Converter.n_to_binary(v[0]), Converter.n_to_binary(v[1]), Converter.n_to_binary(v[2]), Converter.n_to_binary(v[3])];
		let M : [[[Nat8]]] = [[fourteen, eleven, thirteen, nine], [nine, fourteen, eleven, thirteen], [thirteen, nine, fourteen, eleven], [eleven, thirteen, nine, fourteen]];
		
		return [Converter.binary_to_nat8(inner(M[0], v_bin)), Converter.binary_to_nat8(inner(M[1], v_bin)), Converter.binary_to_nat8(inner(M[2], v_bin)), Converter.binary_to_nat8(inner(M[3], v_bin))];	
	};

	//rotates a key-schedule word
	func rot_word(w: [Nat8]) : [Nat8]{
		return [w[1], w[2], w[3], w[0]];
	};

	//substitute operation on a key-schedule word	
	func substitute_word(w: [Nat8]) : [Nat8]{
		return [s_box[Nat8.toNat(w[0])], s_box[Nat8.toNat(w[1])], s_box[Nat8.toNat(w[2])], s_box[Nat8.toNat(w[3])]];
	};
		
	//******************	
	//matrix operations 
	//******************	
		
	//adds two matrices
	func add(M : [[Nat8]], N : [[Nat8]]) : [[Nat8]]{	
		let M_bin : [[[Nat8]]] = Converter.nat8matrix_to_binary(M);
		let N_bin : [[[Nat8]]] = Converter.nat8matrix_to_binary(N);
		
		var output_list : List.List<[Nat8]> = List.nil<[Nat8]>();	
		
		for(i in Iter.range(0,3)){
			var row_list : List.List<Nat8> = List.nil<Nat8>();
			for(j in Iter.range(0,3)){
				let sum_binary : [Nat8] = [(M_bin[i][j][0]+N_bin[i][j][0]) % 2, (M_bin[i][j][1]+N_bin[i][j][1]) % 2, (M_bin[i][j][2]+N_bin[i][j][2]) % 2, (M_bin[i][j][3]+N_bin[i][j][3]) % 2, (M_bin[i][j][4]+N_bin[i][j][4]) % 2, (M_bin[i][j][5]+N_bin[i][j][5]) % 2, (M_bin[i][j][6]+N_bin[i][j][6]) % 2, (M_bin[i][j][7]+N_bin[i][j][7]) % 2];
				let sum : Nat8 = Converter.binary_to_nat8(sum_binary);
				row_list := List.reverse(row_list);
				row_list := List.push(sum, row_list);
				row_list := List.reverse(row_list);
			};
			
			output_list := List.reverse(output_list);
			output_list := List.push(List.toArray(row_list), output_list);
			output_list := List.reverse(output_list);			
		};
		
		return List.toArray(output_list);
	};

	//adds round key matrix to given matrix
	public func add_round_key(M : [[Nat8]], K : [[Nat8]]) : [[Nat8]]{
		return add(M,K);
	};
	
	//substitution step - replaces matrix entries with corresponding sbox entries
	public func substitute(M : [[Nat8]]) : [[Nat8]]{
		var output_list : List.List<[Nat8]> = List.nil<[Nat8]>();	
		for(i in Iter.range(0,3)){	
			output_list := List.reverse(output_list);
			output_list := List.push([s_box[Nat8.toNat(M[i][0])], s_box[Nat8.toNat(M[i][1])], s_box[Nat8.toNat(M[i][2])], s_box[Nat8.toNat(M[i][3])]] , output_list);
			output_list := List.reverse(output_list);
		};	
		return List.toArray(output_list);		
	};

	//inverse substitution step - replaces matrix entries with corresponding inverse-sbox entries
	public func inverse_substitute(M : [[Nat8]]) : [[Nat8]]{
		var output_list : List.List<[Nat8]> = List.nil<[Nat8]>();	
		for(i in Iter.range(0,3)){	
			output_list := List.reverse(output_list);
			output_list := List.push([inv_s_box[Nat8.toNat(M[i][0])], inv_s_box[Nat8.toNat(M[i][1])], inv_s_box[Nat8.toNat(M[i][2])], inv_s_box[Nat8.toNat(M[i][3])]] , output_list);
			output_list := List.reverse(output_list);
		};	
		return List.toArray(output_list);
	};
	
	//shift row step 
	public func shift_rows(M : [[Nat8]]) : [[Nat8]]{
		var output_list : List.List<[Nat8]> = List.nil<[Nat8]>();	
		for(i in Iter.range(0,3)){	
			output_list := List.reverse(output_list);
			output_list := List.push([M[i][(0+i)%4], M[i][(1+i)%4], M[i][(2+i)%4], M[i][(3+i)%4]] , output_list);
			output_list := List.reverse(output_list);
		};
		let output : [[Nat8]] = List.toArray(output_list);
		return output;
	};

	//inverse shift row step 
	public func inverse_shift_rows(M : [[Nat8]]) : [[Nat8]]{
		var output_list : List.List<[Nat8]> = List.nil<[Nat8]>();	
		for(i in Iter.range(0,3)){	
			output_list := List.reverse(output_list);
			output_list := List.push([M[i][(4-i)%4], M[i][(5-i)%4], M[i][(6-i)%4], M[i][(7-i)%4]] , output_list);
			output_list := List.reverse(output_list);
		};
		let output : [[Nat8]] = List.toArray(output_list);
		return output;
	};
	
	//mixes columns of matrix
	public func mix_columns(M : [[Nat8]]) : [[Nat8]]{
		let v0 : [Nat8] = [M[0][0], M[1][0], M[2][0], M[3][0]];
		let v1 : [Nat8] = [M[0][1], M[1][1], M[2][1], M[3][1]];
		let v2 : [Nat8] = [M[0][2], M[1][2], M[2][2], M[3][2]];
		let v3 : [Nat8] = [M[0][3], M[1][3], M[2][3], M[3][3]];
		
		let w0 : [Nat8] = mix_single_column(v0);
		let w1 : [Nat8] = mix_single_column(v1);
		let w2 : [Nat8] = mix_single_column(v2);
		let w3 : [Nat8] = mix_single_column(v3);

		var output : [[Nat8]] = [[w0[0], w1[0], w2[0], w3[0]], [w0[1], w1[1], w2[1], w3[1]], [w0[2], w1[2], w2[2], w3[2]], [w0[3], w1[3], w2[3], w3[3]]];
		return output;
	};

	//inverse mixes columns of matrix	
	public func inverse_mix_columns(M : [[Nat8]]) : [[Nat8]]{
		let v0 : [Nat8] = [M[0][0], M[1][0], M[2][0], M[3][0]];
		let v1 : [Nat8] = [M[0][1], M[1][1], M[2][1], M[3][1]];
		let v2 : [Nat8] = [M[0][2], M[1][2], M[2][2], M[3][2]];
		let v3 : [Nat8] = [M[0][3], M[1][3], M[2][3], M[3][3]];
		
		let w0 : [Nat8] = inverse_mix_single_column(v0);
		let w1 : [Nat8] = inverse_mix_single_column(v1);
		let w2 : [Nat8] = inverse_mix_single_column(v2);
		let w3 : [Nat8] = inverse_mix_single_column(v3);

		var output : [[Nat8]] = [[w0[0], w1[0], w2[0], w3[0]], [w0[1], w1[1], w2[1], w3[1]], [w0[2], w1[2], w2[2], w3[2]], [w0[3], w1[3], w2[3], w3[3]]];
		return output;
	};
	
	//******************	
	//AES macro operations 
	//******************	
	
	//returns the key schedule array from a given key (note: the original key is the zeroeth entry of the array)
	public func key_schedule(K : [[Nat8]]) : [[[Nat8]]]{

		var output_list : List.List<[[Nat8]]> = List.nil<[[Nat8]]>();
		
		output_list := List.push(K, output_list);
		
		var v0 : [Nat8] = [K[0][0], K[1][0], K[2][0], K[3][0]];
		var v1 : [Nat8] = [K[0][1], K[1][1], K[2][1], K[3][1]];
		var v2 : [Nat8] = [K[0][2], K[1][2], K[2][2], K[3][2]];
		var v3 : [Nat8] = [K[0][3], K[1][3], K[2][3], K[3][3]];
		
		//Debug.print("########################");

		////Debug.print("Key schedule key");
		////Debug.print(Nat8.toText(v3[0]) # " " # Nat8.toText(v0[0]) # " " # Nat8.toText(v1[0]) # " " # Nat8.toText(v2[0]));
		////Debug.print(Nat8.toText(v3[1]) # " " # Nat8.toText(v0[1]) # " " # Nat8.toText(v1[1]) # " " # Nat8.toText(v2[1]));
		////Debug.print(Nat8.toText(v3[2]) # " " # Nat8.toText(v0[2]) # " " # Nat8.toText(v1[2]) # " " # Nat8.toText(v2[2]));
		////Debug.print(Nat8.toText(v3[3]) # " " # Nat8.toText(v0[3]) # " " # Nat8.toText(v1[3]) # " " # Nat8.toText(v2[3]));
		
		for (i in Iter.range(1,10)){
			let w0 : [Nat8] = xor(v0, xor(substitute_word(rot_word(v3)), [round_constants[i], Nat8.fromNat(0), Nat8.fromNat(0), Nat8.fromNat(0)]));
			let w1 : [Nat8] = xor(v1, w0);
			let w2 : [Nat8] = xor(v2, w1);
			let w3 : [Nat8] = xor(v3, w2);

			////Debug.print("Key schedule key");
			////Debug.print(Nat8.toText(w3[0]) # " " # Nat8.toText(w0[0]) # " " # Nat8.toText(w1[0]) # " " # Nat8.toText(w2[0]));
			////Debug.print(Nat8.toText(w3[1]) # " " # Nat8.toText(w0[1]) # " " # Nat8.toText(w1[1]) # " " # Nat8.toText(w2[1]));
			////Debug.print(Nat8.toText(w3[2]) # " " # Nat8.toText(w0[2]) # " " # Nat8.toText(w1[2]) # " " # Nat8.toText(w2[2]));
			////Debug.print(Nat8.toText(w3[3]) # " " # Nat8.toText(w0[3]) # " " # Nat8.toText(w1[3]) # " " # Nat8.toText(w2[3]));

			output_list := List.reverse(output_list);			
			output_list := List.push([[w0[0], w1[0], w2[0], w3[0]], [w0[1], w1[1], w2[1], w3[1]], [w0[2], w1[2], w2[2], w3[2]], [w0[3], w1[3], w2[3], w3[3]]], output_list);
			output_list := List.reverse(output_list);			
			
			v0 := w0;
			v1 := w1;
			v2 := w2;
			v3 := w3;
		};
		
		return List.toArray(output_list);
	};
	
	//uses AES to encypt a matrix with a key
	public func encrypt_matrix (M : [[Nat8]], K : [[Nat8]]) : [[Nat8]]{
		let KS : [[[Nat8]]] = key_schedule(K);
		var output : [[Nat8]] = M; 
		//Debug.print("M is");		
		//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
		//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
		//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
		//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));


		output := add_round_key(output, K);	
		
		//Debug.print("***************************************");

		//Debug.print("M + round key is");		
		//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
		//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
		//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
		//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));
		
		for (i in Iter.range(1, KS.size()-2)){
			let L : [[Nat8]] = KS[i];
			output := substitute(output);
			
			//Debug.print("substitute");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := shift_rows(output);
			
			//Debug.print("shift rows");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := mix_columns(output);	
			
			//Debug.print("mix columns");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := add_round_key(output, L);	
				
			//Debug.print("add round key");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));
		};

		output := substitute(output);
		output := shift_rows(output);
		output := add_round_key(output, KS[10]);		
		
		return output;
	};

	//uses inverse AES to decrypt a matrix with a key
	public func inverse_encrypt_matrix (M : [[Nat8]], K : [[Nat8]]) : [[Nat8]]{
		let KS : [[[Nat8]]] = key_schedule(K);
		var output : [[Nat8]] = M;
		output := add_round_key(output, KS[10]);
		output := inverse_shift_rows(output);
		output := inverse_substitute(output);
		
		//Debug.print("******************** INVERTING MATRIX NOW ******************");
		
		//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
		//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
		//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
		//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));
		
		for (i in Iter.range(1, KS.size()-2)){
			let L : [[Nat8]] = KS[KS.size()-1-i];

			output := add_round_key(output, L);	
			//Debug.print("inverse add round key");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := inverse_mix_columns(output);				
			//Debug.print("inverse mix columns");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := inverse_shift_rows(output);
			//Debug.print("inverse shift rows");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));

			output := inverse_substitute(output);		
			//Debug.print("inverse substitute");
			//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
			//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
			//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
			//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));
		};

		output := add_round_key(output, KS[0]);		

		//Debug.print("FINAL");
		//Debug.print(Nat8.toText(output[0][0]) # " " # Nat8.toText(output[0][1]) # " " # Nat8.toText(output[0][2]) # " " # Nat8.toText(output[0][3]));
		//Debug.print(Nat8.toText(output[1][0]) # " " # Nat8.toText(output[1][1]) # " " # Nat8.toText(output[1][2]) # " " # Nat8.toText(output[1][3]));
		//Debug.print(Nat8.toText(output[2][0]) # " " # Nat8.toText(output[2][1]) # " " # Nat8.toText(output[2][2]) # " " # Nat8.toText(output[2][3]));
		//Debug.print(Nat8.toText(output[3][0]) # " " # Nat8.toText(output[3][1]) # " " # Nat8.toText(output[3][2]) # " " # Nat8.toText(output[3][3]));
		
		return output;
	};
	
	//encrypts a block of text (1 block = 16 characters)
	public func encrypt_block (word : Text, key : Text, padding : Text) : Text { //output is doublehex			
		var a : [Nat8] = Converter.string_to_nat8(word);
		
		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16);
		};

		let M : [[Nat8]] = array_to_matrix(a);
		let k_arr : [Nat8] = Converter.string_to_nat8(key);
		let K : [[Nat8]] = array_to_matrix(k_arr);		
		
		let result_matrix : [[Nat8]] = encrypt_matrix(M,K);
		let result_arr : [Nat8] = matrix_to_array(result_matrix);
						
		let result : Text = Converter.nat8_to_doublehex(result_arr);
		return result;
	};			
	
	//encrypts a block of hex text with a hex key (1 block = 32 hex characters)
	public func encrypt_hex_block (word : Text, key : Text, padding : Text) : Text { //output is doublehex			
		var a : [Nat8] = Converter.hex_to_nat8(word);
				
		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16);
		};

		let M : [[Nat8]] = array_to_matrix(a);
		let k_arr : [Nat8] = Converter.hex_to_nat8(key);
		let K : [[Nat8]] = array_to_matrix(k_arr);		
		
		let result_matrix : [[Nat8]] = encrypt_matrix(M,K);
		let result_arr : [Nat8] = matrix_to_array(result_matrix);
						
		let result : Text = Converter.nat8_to_doublehex(result_arr);
		return result;
	};			

	//decrypts a block of hex text with a hex key (1 block = 32 hex characters)
	public func decrypt_hex_block (word : Text, key : Text, padding : Text) : Text { //output is doublehex			
		var a : [Nat8] = Converter.hex_to_nat8(word);
		
		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16);
		};

		let M : [[Nat8]] = array_to_matrix(a);
		let k_arr : [Nat8] = Converter.hex_to_nat8(key);
		let K : [[Nat8]] = array_to_matrix(k_arr);		
		
		let result_matrix : [[Nat8]] = inverse_encrypt_matrix(M, K);
		let result_arr : [Nat8] = matrix_to_array(result_matrix);
						
		let result : Text = Converter.nat8_to_doublehex(result_arr);
		return result;
	};			

	//encrypts a block of hex text with a matrix key (1 block = 32 hex characters)
	public func encrypt_hex_block_matkey (word : Text, key : [Nat8], padding : Text) : Text { //output is doublehex			
		var a : [Nat8] = Converter.hex_to_nat8(word);
		
		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16);
		};

		let M : [[Nat8]] = array_to_matrix(a);
		let K : [[Nat8]] = array_to_matrix(key);		
		
		let result_matrix : [[Nat8]] = encrypt_matrix(M, K);
		let result_arr : [Nat8] = matrix_to_array(result_matrix);
						
		let result : Text = Converter.nat8_to_doublehex(result_arr);
		return result;
	};			

	//decrypts a block of hex text with a matrix key (1 block = 32 hex characters)
	public func decrypt_hex_block_matkey (word : Text, key : [Nat8], padding : Text) : Text { //output is doublehex			
		var a : [Nat8] = Converter.hex_to_nat8(word);
		
		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16);
		};

		let M : [[Nat8]] = array_to_matrix(a);
		let K : [[Nat8]] = array_to_matrix(key);		
		
		let result_matrix : [[Nat8]] = inverse_encrypt_matrix(M, K);
		let result_arr : [Nat8] = matrix_to_array(result_matrix);
						
		let result : Text = Converter.nat8_to_doublehex(result_arr);
		return result;
	};

	// encrypts a hex string, block by block
	public func encrypt_hex(word : Text, key : Text, padding : Text) : Text {
		var a : [Nat8] = Converter.hex_to_nat8(word);
		
		let length : Nat = a.size()-1;
		let num_blocks : Nat = 1 + length / 16;
		
		//Debug.print("num_blocks is " # Nat.toText(num_blocks));

		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16*num_blocks);
		};

		let k_arr : [Nat8] = Converter.hex_to_nat8(key);
		let K : [[Nat8]] = array_to_matrix(k_arr);					
		
		var result : Text = "";
		
		for(i in Iter.range(0, num_blocks-1)){
			let b : [Nat8] = [a[16*i], a[16*i+1], a[16*i+2], a[16*i+3], a[16*i+4], a[16*i+5], a[16*i+6], a[16*i+7], a[16*i+8], a[16*i+9], a[16*i+10], a[16*i+11], a[16*i+12], a[16*i+13], a[16*i+14], a[16*i+15]];
			let M : [[Nat8]] = array_to_matrix(b);

			let block_result_matrix : [[Nat8]] = encrypt_matrix(M,K);
			let block_result_arr : [Nat8] = matrix_to_array(block_result_matrix);
			let block_result : Text = Converter.nat8_to_doublehex(block_result_arr);
			result := result # block_result;
		};
		
		return result;
	};
	
	// decrypts a hex string, block by block
	public func decrypt_hex(word : Text, key : Text, padding : Text) : Text {
		var a : [Nat8] = Converter.hex_to_nat8(word);
		
		let length : Nat = a.size()-1;
		let num_blocks : Nat = 1 + length / 16;
		
		//Debug.print("num_blocks is " # Nat.toText(num_blocks));

		if(padding == "0"){
			a := Padding.pad_0_to_n(a, 16*num_blocks);
		};

		let k_arr : [Nat8] = Converter.hex_to_nat8(key);
		let K : [[Nat8]] = array_to_matrix(k_arr);					
		
		var result : Text = "";
		
		for(i in Iter.range(0, num_blocks-1)){
			let b : [Nat8] = [a[16*i], a[16*i+1], a[16*i+2], a[16*i+3], a[16*i+4], a[16*i+5], a[16*i+6], a[16*i+7], a[16*i+8], a[16*i+9], a[16*i+10], a[16*i+11], a[16*i+12], a[16*i+13], a[16*i+14], a[16*i+15]];
			let M : [[Nat8]] = array_to_matrix(b);

			let block_result_matrix : [[Nat8]] = inverse_encrypt_matrix(M,K);
			let block_result_arr : [Nat8] = matrix_to_array(block_result_matrix);
			let block_result : Text = Converter.nat8_to_doublehex(block_result_arr);
			result := result # block_result;
		};
		
		return result;
	};	
		
};
