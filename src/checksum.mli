type bigstring =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

val digest : ?off:int -> ?len:int -> bigstring -> int
val digest_cstruct : Cstruct.t -> int
val digest_string : ?off:int -> ?len:int -> string -> int
val digest_strings : string list -> int
