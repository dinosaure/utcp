(* This module can be seen as a reimplementation of [Hashtbl] with a specialized
   key that corresponds to the header of IPv4 packets. The advantage of this
   implementation is:
   1) the performance compared to [Hashtbl] for searching for a fragment
      according to its header is equivalent
   2) the deletion of an element from the [Table] because the packet seems
      corrupted is in O(1) as long as it has already been found

   For the second point, we know that deletion occurs in 2 cases:
   - the case where the packet found in the table is corrupted, in which case we
     are faster than [Hashtbl.find; Hashtbl.remove].
   - the case where we have to remove expired packets (which corresponds to
     [Hashtbl.iter (Hashtbl.remove)]).

   To achieve this result, instead of using a simple list as is the case in
   [Hashtbl], a doubly linked list is used, which makes it possible to delete an
   element without having to go through the [Hashtbl] again as long as there is
   a representation of this element in the [Table] (a [node]).

   Finally, a last difference compared to [Hashtbl] is that the maximum number
   of elements that can be stored in the [Table] is fixed! It is not really a
   LRU cache (there is no promotion of elements according to information) but
   the memory usage of this [table] should also be fixed.
*)

type seq =
  { mutable prev : seq; mutable next : seq }

type node =
  { mutable prev : seq
  ; mutable next : seq
  ; key : Fragment.header
  ; idx : int
  ; mutable active : bool }

external seq_of_node : node -> seq = "%identity"
external node_of_seq : seq -> node = "%identity"

let add_node seq key idx =
  let node = { prev= seq; next= seq.next; key; idx; active= true } in
  seq.next.prev <- seq_of_node node;
  seq.next <- seq_of_node node

let key { key; _ } = key
let none = None

type 'a t =
  { values : 'a option array
  ; keys : seq array
  ; mutable size : int
  ; max : int
  ; mask : int }

let hash t { Fragment.src; dst; _ } =
  if Sys.word_size = 32
  then
    let a, b = Ipaddr.V4.to_int16 dst in
    Hashtbl.hash ((a lsl 16) lor b) land t.mask
  else
    let a, b = Ipaddr.V4.to_int16 src in
    let c, d = Ipaddr.V4.to_int16 dst in
    Hashtbl.hash ((a lsl 48) lor (b lsl 32) lor (c lsl 16) lor d) land t.mask

let value t node =
  if node.active
  then Array.unsafe_get t.values node.idx
  else none

let remove t node =
  if node.active
  then begin
    node.active <- false;
    t.values.(node.idx) <- none;
    t.size <- t.size - 1;
    let seq = seq_of_node node in
    seq.prev.next <- node.next;
    seq.next.prev <- node.prev
  end

let pot x = x land (x - 1) == 0 && x != 0

let unsafe_ctz n =
  let t = ref 1 in
  let r = ref 0 in
  while n land !t == 0 do
    t := !t lsl 1;
    incr r
  done; !r

let new_seq _ =
  let rec seq = { prev= seq; next= seq } in seq

let make ?(max= 1 lsl 4) () =
  if pot max == false
  then invalid_arg "Table.make: max must be a power of two";
  { values= Array.make max None
  ; keys= Array.init max new_seq
  ; size= 0
  ; max
  ; mask= (1 lsl unsafe_ctz max) - 1 }

let is_full t = t.size == t.max

let rec go key root curr =
  if curr == root then raise_notrace Not_found;
  let node = node_of_seq curr in
  if node.active
  && compare node.key key == 0
  then node
  else go key root node.next

let node_of_key t ~key =
  let root = Array.unsafe_get t.keys (hash t key) in
  let seq = ref root.next in
  if root == !seq
  then raise_notrace Not_found ;
  if Stdlib.compare (node_of_seq !seq).key key == 0
  && (node_of_seq !seq).active
  then node_of_seq !seq
  else begin
    seq := !seq.next;
    if root == !seq
    then raise_notrace Not_found ;
    if Stdlib.compare (node_of_seq !seq).key key == 0
    && (node_of_seq !seq).active
    then node_of_seq !seq
    else begin
      seq := !seq.next;
      if root == !seq
      then raise_notrace Not_found;
      if Stdlib.compare (node_of_seq !seq).key key == 0
      then node_of_seq !seq
      else go key root !seq.next
    end
  end

let iter ~fn t =
  let rec go root curr =
    if curr != root
    then begin
      let node = node_of_seq curr in
      if node.active
      then fn node;
      go root node.next
    end in
  for idx = 0 to Array.length t.keys - 1 do
    let root = Array.unsafe_get t.keys idx in
    go root root.next
  done

let find t key =
  let node = node_of_key t ~key in
  match Array.unsafe_get t.values (node.idx) with
  | Some value -> (node, value)
  | None -> raise_notrace Not_found

let next_empty arr =
  let len = Array.length arr in
  let rec go idx =
    if idx < len
    then match Array.unsafe_get arr idx with
      | None -> idx
      | _ -> go (idx+1)
    else assert false in
  go 0

let add t key value =
  if is_full t
  then invalid_arg "Table is full";
  let idx = next_empty t.values in
  t.values.(idx) <- Some value;
  let h = hash t key in
  add_node t.keys.(h) key idx;
  t.size <- t.size + 1
