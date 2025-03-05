type 'a t
type node

val make : ?max:int -> unit -> 'a t
val key : node -> Fragment.header
val value : 'a t -> node -> 'a option
val remove : 'a t -> node -> unit
val find : 'a t -> Fragment.header -> node * 'a
val iter : fn:(node -> unit) -> 'a t -> unit
val is_full : 'a t -> bool
val add : 'a t -> Fragment.header -> 'a -> unit
