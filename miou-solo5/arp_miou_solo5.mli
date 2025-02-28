module Ethernet = Ethernet_miou_solo5

module Packet : sig
  type t
end

type t

val create :
     ?timeout:int
  -> ?retries:int
  -> ?src:Logs.Src.t
  -> ?ipaddr:Ipaddr.V4.t
  -> Ethernet.t
  -> (t, [> `MTU_too_small ]) result

val macaddr : t -> Macaddr.t

val input :
     t
  -> Bstr.t Ethernet.packet
  -> unit

val tick : t -> unit
val set_ips : t -> Ipaddr.V4.t list -> unit
val query :
     t
  -> Ipaddr.V4.t
  -> (Macaddr.t, [> `Exn of exn | `Timeout | `Clear ]) result
