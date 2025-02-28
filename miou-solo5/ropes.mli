type fix = |
type unknown = |

type 'a t =
  | Str : string -> fix t
  | Unknown : 'a size -> 'a t
  | App : fix t * 'a t * int * 'a size -> 'a t
and 'a size =
  | Length : int -> fix size
  | Limitless : unknown size

exception Out_of_bounds
exception Overlap

val length : 'a t -> 'a size
val insert : off:int -> string -> 'a t -> 'a t
val fix : max:int -> unknown t -> fix t
val to_bytes : fix t -> Diet.t * bytes
