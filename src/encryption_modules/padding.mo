import List "mo:base/List";
import Iter "mo:base/Iter";
import Nat8 "mo:base/Nat8";

module {

	//******************	
	//padding functions
	//******************	
	
	//pads an array with 0 until it hits a size n
	public func pad_0_to_n (a: [Nat8], n : Nat) : [Nat8]{
		var result_list : List.List<Nat8> = List.fromArray(a);
		
		let d : Nat = n - a.size();
		
		if(d > 0){
			for(i in Iter.range(0, d-1)){
				result_list := List.reverse(result_list);
				result_list := List.push(Nat8.fromNat(0), result_list);
				result_list := List.reverse(result_list);
			};
		};
		
		return List.toArray(result_list);
	};

};