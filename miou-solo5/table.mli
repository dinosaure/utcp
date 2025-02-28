type 'a t
type node

val make : ?max:int -> unit -> 'a t
val key : node -> Fragment.t
val value : 'a t -> node -> 'a option
val remove : 'a t -> node -> unit
val find : 'a t -> Fragment.t -> node * 'a
val iter : fn:(node -> unit) -> 'a t -> unit
val is_full : 'a t -> bool
val add : 'a t -> Fragment.t -> 'a -> unit
