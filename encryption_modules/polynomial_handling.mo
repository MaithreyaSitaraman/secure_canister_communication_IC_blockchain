/**
 * Module      : polynomial_handling.mo
 * Description : Mathematics module that handles Addition and Multiplication in Polynomial rings k[X]/(f)
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

	// arrays <-> polynomials via, for example [1,0,0] -> x^2, [1,0,0,0,1,0] -> x^5 + x

	func degree(p : [Nat8]) : Nat {
		for(i in Iter.range(0, p.size() -1)){
			if(p[i] != Nat8.fromNat(0)){
				return p.size()-1-i;
			};
		};
		return 0;
	};
	
	public func add(p1 : [Nat8], p2 : [Nat8]) : [Nat8]{
		
		let l1 : Nat = p1.size();
		let l2 : Nat = p2.size();

		var q1_list : List.List<Nat8> = List.nil<Nat8>();	
		var q2_list : List.List<Nat8> = List.nil<Nat8>();	
		
		if (l1 > l2){
			for (i in Iter.range(0,l2-1)){

				q1_list := List.reverse(q1_list);
				q1_list := List.push(p1[i], q1_list);
				q1_list := List.reverse(q1_list);	
				
				q2_list := List.reverse(q2_list);
				q2_list := List.push(p2[i], q2_list);
				q2_list := List.reverse(q2_list);			
				
			};
			for (i in Iter.range(l2,l1-1)){
				q1_list := List.reverse(q1_list);
				q1_list := List.push(p1[i], q1_list);
				q1_list := List.reverse(q1_list);	
				
				q2_list := List.push(Nat8.fromNat(0), q2_list);
			};
		}
		else if (l2 > l1) {

			for (i in Iter.range(0,l1-1)){

				q1_list := List.reverse(q1_list);
				q1_list := List.push(p1[i], q1_list);
				q1_list := List.reverse(q1_list);	
				
				q2_list := List.reverse(q2_list);
				q2_list := List.push(p2[i], q2_list);
				q2_list := List.reverse(q2_list);			
				
			};
			for (i in Iter.range(l1,l2-1)){
				q2_list := List.reverse(q2_list);
				q2_list := List.push(p2[i], q2_list);
				q2_list := List.reverse(q2_list);	
				
				q1_list := List.push(Nat8.fromNat(0), q1_list);
			};
		
		}
		else {
			for (i in Iter.range(0, l1-1)){
				q1_list := List.reverse(q1_list);
				q1_list := List.push(p1[i], q1_list);
				q1_list := List.reverse(q1_list);	
				
				q2_list := List.reverse(q2_list);
				q2_list := List.push(p2[i], q2_list);
				q2_list := List.reverse(q2_list);						
			};
		};
		
		let q1 : [Nat8] = List.toArray(q1_list);
		let q2 : [Nat8] = List.toArray(q2_list);
		
		var output_list : List.List<Nat8> = List.nil<Nat8>();	
		
		for(i in Iter.range(0, q1.size()-1)){
			output_list := List.reverse(output_list);
			output_list := List.push((q1[i]+q2[i]) % 2, output_list);
			output_list := List.reverse(output_list);
		};
		
		return List.toArray(output_list);
	};
	
	public func multiply(p1 : [Nat8], p2 : [Nat8]) : [Nat8] {
		
		let l1 : Nat = p1.size();
		let l2 : Nat = p2.size();
		
		let p : [var Nat8] = Array.init<Nat8>(l1+l2-1, Nat8.fromNat(0));
		
		for (i in Iter.range(0, l1-1)){
			for (j in Iter.range(0, l2-1)){
				let deg1 : Nat = l1 - i - 1;
				let deg2 : Nat = l2 - j -1;
				let deg : Nat = deg1 + deg2;
				let idx : Nat = l1+l2-2 - deg;
								
				p[idx] := (p[idx] + p1[i]*p2[j]) % 2;	
							
			};
		};
		
		var output_list : List.List<Nat8> = List.nil<Nat8>();	
		for ( i in Iter.range(0, l1+l2-2)){
			output_list := List.reverse(output_list);
			output_list := List.push(p[i], output_list);
			output_list := List.reverse(output_list);
		};
		
		return  List.toArray(output_list);
	};
	
	func truncate_to_8(p : [Nat8]) : [Nat8]{
		if(p.size() > 8){
			let d : Nat = p.size()-8;
			var p_list : List.List<Nat8> = List.nil<Nat8>();
			
			for(i in Iter.range(d, p.size()-1)){
				p_list := List.reverse(p_list);
				p_list := List.push(p[i], p_list);
				p_list := List.reverse(p_list);
			};
			
			return List.toArray(p_list);
		};
		return p;
	};
			
	public func remainder(p0 : [Nat8], p : [Nat8]) : [Nat8]{
		
		if(degree(p0) < degree(p)){
			return p0;
		}
		else{

			// p0 = p * coeff x^{deg diff} + r => r = p0 + p * coeff x^{deg diff} [note: we are mod 2]
			
			let d : Nat = degree(p0) - degree(p);
			
			var q_list : List.List<Nat8> = List.nil<Nat8>();
			for (i in Iter.range(0, d-1)){
				q_list := List.push(Nat8.fromNat(0), q_list);
			};
			q_list := List.push(Nat8.fromNat(1), q_list);
			
			let q : [Nat8] = List.toArray(q_list);
			
			let r : [Nat8] = add(p0, multiply(q,p));
				
			return remainder(r, p);
		};
	};
	
	public func mult_for_aes128(p1 : [Nat8], p2: [Nat8]) : [Nat8]{
		let n1 : Nat8 = Nat8.fromNat(1);
		let n0 : Nat8 = Nat8.fromNat(0);
		
		let p : [Nat8] = [n1,n0,n0,n0,n1,n1,n0,n1,n1];
		
		return truncate_to_8(remainder(multiply(p1, p2), p))
	};
	 
};