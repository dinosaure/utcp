module Ethernet = Ethernet_miou_solo5

module Packet : sig
  type t
end

type 'a t

val create :
     ?timeout:int
  -> ?retries:int
  -> ?src:Logs.Src.t
  -> ?ipaddr:Ipaddr.V4.t
  -> Ethernet.t
  -> ('a t, [> `MTU_too_small ]) result

val macaddr : 'a t -> Macaddr.t

val input :
     'a t
  -> Bstr.t Ethernet.packet
  -> 'a t * (Macaddr.t * 'a) option

val tick : 'a t -> 'a t * 'a list
