/**
 * Module      : converter.mo
 * Description : Handles conversions between binary, Nat8, hex, unicode etc..
 * Copyright   : Cramium Inc.
 * Creator   : Maithreya Sitaraman
 * License  : Creative Commons
 */

import Array "mo:base/Array";
import List "mo:base/List";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Debug "mo:base/Debug";
import Char "mo:base/Char";

module {

	let hex_map : [Text] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
	let hex_chars : [Char] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
	
	let unicode_nums : [Nat8] = [32, 33, 44, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122];
	let unicode_chars: [Char] = [' ', '!', ',', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

	//******************	
	//converting from binary
	//******************	
	
	//binary array to hex string
	public func binary_to_hex(bin_arr : [Nat8]) : Text {
	
		var padded : List.List<Nat8> = List.fromArray(bin_arr);
	
		let remainder : Int = bin_arr.size() % 4;
		
		var to_pad : Int = 0;		
		
		if(remainder != 0){
			to_pad := 4 - remainder;		
		};

		for(i in Iter.range(0,to_pad-1)){
			padded := List.reverse(padded);
			padded := List.push(Nat8.fromNat(0), padded);
			padded := List.reverse(padded);
		};
		
		let num_blocks : Int = List.size(padded) / 4;
		let padded_arr : [Nat8] = List.toArray(padded);
		
		var output : Text = "";
		for(i in Iter.range(0,num_blocks-1)){
			let n : Nat8 = 8*padded_arr[4*i]+4*padded_arr[4*i+1]+2*padded_arr[4*i+2]+padded_arr[4*i+3];
			output := output # hex_map[Nat8.toNat(n)];
		};
		
		return output;
	};
	
	//binary array to Nat8 number (a size 8 array -> a number)		
	public func binary_to_nat8(bin_arr : [Nat8]) : Nat8 {
		var result : Nat = 0;
		for (i in Iter.range(0,7)){
			if (bin_arr[i] == 1){
				result += 2**(7-i);			
			};
		};
		return Nat8.fromNat(result);
	};
	
	//binary array to Nat8 array (e.g a size 32 array -> a size 4 array)	
	public func binaryarr_to_nat8arr (b : [Nat8]) : [Nat8] {
		
		var result_list : List.List<Nat8> = List.nil<Nat8>();
		
		let iterations : Nat = b.size() / 8;
		
		for( i in Iter.range(0, iterations-1)){
			let next : [Nat8] = [b[8*i], b[8*i+1], b[8*i+2], b[8*i+3], b[8*i+4], b[8*i+5], b[8*i+6], b[8*i+7]];
			result_list := List.push(binary_to_nat8(next), result_list);
		};
		
		result_list := List.reverse(result_list);
		
		return List.toArray(result_list);
	};
	
	//******************	
	//converting from Nat8
	//******************	
	
	//Nat8 number to a binary array of size 8
	public func n_to_binary (n : Nat8) : [Nat8]{
		var sum : Nat8 = Nat8.fromNat(0);
		var result_list : List.List<Nat8> = List.nil<Nat8>();
		
		for(i in Iter.range(0,7)){
			let j : Nat8 = Nat8.fromNat(7-i);
			if(sum + Nat8.fromNat(2)**j > n){
				result_list := List.reverse(result_list);
				result_list := List.push(Nat8.fromNat(0), result_list);
				result_list := List.reverse(result_list);				
			}
			else{
				result_list := List.reverse(result_list);
				result_list := List.push(Nat8.fromNat(1), result_list);
				result_list := List.reverse(result_list);				

				sum := sum + 2**j;
			};
		};
		
		return List.toArray(result_list);
	};
	
	//Nat8 array -> binary array (e.g a Nat8 array of length5 -> Binary array of length 40)
	public func nat8_to_binary (nat8_arr: [Nat8]) : [Nat8]{
		var result_list : List.List<Nat8> = List.nil<Nat8>();
		
		for(i in Iter.range(0, nat8_arr.size()-1)){
			let a : [Nat8] = n_to_binary(nat8_arr[i]);
			for(j in Iter.range(0, a.size()-1)){
				result_list := List.reverse(result_list);
				result_list := List.push(a[j], result_list);
				result_list := List.reverse(result_list);								
			};
		};
		
		return List.toArray(result_list);	
	};
	
	//takes in Nat8 array, and replaces each number in array with the binary of that number
	public func nat8_to_doublebinary (nat8_arr: [Nat8]) : [[Nat8]]{
		var result_list : List.List<[Nat8]> = List.nil<[Nat8]>();
		
		for(i in Iter.range(0, nat8_arr.size()-1)){
			let a : [Nat8] = n_to_binary(nat8_arr[i]);
			result_list := List.reverse(result_list);
			result_list := List.push(a, result_list);
			result_list := List.reverse(result_list);								
		};
		
		return List.toArray(result_list);	
	};

	//takes in Nat8 matrix, and replaces each number in matrix with the binary of that number	
	public func nat8matrix_to_binary (M: [[Nat8]]) : [[[Nat8]]]{
		var result_list : List.List<[[Nat8]]> = List.nil<[[Nat8]]>();
		
		for(i in Iter.range(0, M.size()-1)){
			result_list := List.reverse(result_list);
			result_list := List.push(nat8_to_doublebinary(M[i]), result_list);
			result_list := List.reverse(result_list);			
		};
		
		return List.toArray(result_list);	
	};
	
	//Nat8 array to a hex string. (e.g an array of length 10 produces Text with 20 characters)
	public func nat8_to_doublehex (a : [Nat8]) : Text{
		var result : Text = "";
		for (n in Iter.fromArray(a)){
			let n_bin : [Nat8] = n_to_binary(n);
			let b1 : [Nat8] = [n_bin[0], n_bin[1], n_bin[2], n_bin[3]];
			let b2 : [Nat8] = [n_bin[4], n_bin[5], n_bin[6], n_bin[7]];
			result := result # binary_to_hex(b1) # binary_to_hex(b2);
		};
		return result;
	};
	
	public func nat8_to_string(a : [Nat8]) : Text{
		var result : Text = "";
		for (i in Iter.range(0, a.size()-1)){
			for (j in Iter.range(0, unicode_nums.size()-1)){
				if(unicode_nums[j] == a[i]){
					result := result # Char.toText(unicode_chars[j]);
				};
			};
		};
		return result
	};
	
	//******************	
	//converting from String
	//******************	
	
	//text -> Nat8 array, replacing every character with the corresponding number
	public func string_to_nat8( mytext : Text) : [Nat8] {

		var result_list : List.List<Nat8> = List.nil<Nat8>();

		for (c in mytext.chars()){
			for(i in Iter.range(0, unicode_chars.size()-1)){
				if(unicode_chars[i] == c){
					result_list := List.reverse(result_list);
					result_list := List.push(unicode_nums[i], result_list);
					result_list := List.reverse(result_list);
				};
			};
		};
	
		return List.toArray(result_list);
	};
	
	//unicode Text -> hex text (e.g length 10 unicode -> length 20 hex)
	public func unicode_to_doublehex (word : Text) : Text{
		let a : [Nat8] = string_to_nat8(word);
		var result : Text = "";
		for (n in Iter.fromArray(a)){
			let n_bin : [Nat8] = n_to_binary(n);
			let b1 : [Nat8] = [n_bin[0], n_bin[1], n_bin[2], n_bin[3]];
			let b2 : [Nat8] = [n_bin[4], n_bin[5], n_bin[6], n_bin[7]];
			result := result # binary_to_hex(b1) # binary_to_hex(b2);
		};
		return result;
	};
	
	
	//alternative implementation of unicode_to_doublehex (identical outputs)
	public func unicode_to_hex (word : Text) : Text {
		let a : [Nat8] = string_to_nat8(word);
		return nat8_to_doublehex(a);
	};
	

	//******************	
	//converting from Hex
	//******************	
	
	//hex -> binary (e.g hex with 10 chars -> length 40 binary array)
	public func hex_to_binary( hex_word: Text) : [Nat8]{
		var result_list : List.List<Nat8> = List.nil<Nat8>();

		for (c in hex_word.chars()){
			var c_index : Nat = 0;
			for(i in Iter.range(0, hex_chars.size()-1)){
				if(hex_chars[i] == c){
					c_index := i;
				};
			};
			
			let c_bin : [Nat8] = n_to_binary(Nat8.fromNat(c_index));
			
			result_list := List.reverse(result_list);
			result_list := List.push(c_bin[4], result_list);
			result_list := List.push(c_bin[5], result_list);
			result_list := List.push(c_bin[6], result_list);
			result_list := List.push(c_bin[7], result_list);
			result_list := List.reverse(result_list);			
		};
		
		return List.toArray(result_list);
	};
	
	//hex -> Nat8 (e.g hex with 10 chars -> length 5 Nat8 array)		
	public func hex_to_nat8 (hex_word : Text) : [Nat8]{
		let bin_word : [Nat8] = hex_to_binary(hex_word);
		return binaryarr_to_nat8arr(bin_word);
	};
	
};