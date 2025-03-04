module Ethernet = Ethernet_miou_solo5

type error =
  [ `Exn of exn
  | `Timeout
  | `Clear ]

val pp_error : error Fmt.t

type t

val create :
     ?timeout:int
  -> ?retries:int
  -> ?src:Logs.Src.t
  -> ?ipaddr:Ipaddr.V4.t
  -> Ethernet.t
  -> (t, [> `MTU_too_small ]) result

val macaddr : t -> Macaddr.t
val input : t -> string Ethernet.packet -> unit
val tick : t -> unit
val set_ips : t -> Ipaddr.V4.t list -> unit
val query : t -> Ipaddr.V4.t -> (Macaddr.t, [> error ]) result
