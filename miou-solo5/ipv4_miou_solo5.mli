module Ethernet = Ethernet_miou_solo5
module ARPv4 = Arp_miou_solo5

module Static : sig
  type t

  type packet =
    { src : Ipaddr.V4.t
    ; dst : Ipaddr.V4.t
    ; protocol : protocol
    ; uid : int }

  and protocol = ICMP | TCP | UDP

  val create :
       ?cache:int
    -> ?to_expire:int
    -> Ethernet.t
    -> ARPv4.t
    -> ?gateway:Ipaddr.V4.t
    -> ?handler:((packet * string) list -> unit)
    -> Ipaddr.V4.Prefix.t
    -> (t, [> `MTU_too_small ]) result

  val write :
       t
    -> finally:(string list -> string)
    -> ?ttl:int
    -> ?src:Ipaddr.V4.t
    -> Ipaddr.V4.t
    -> protocol
    -> ?size:int
    -> string list
    -> (unit, [> `Route_not_found ]) result

  val input : t -> Bstr.t Ethernet.packet -> unit
  val set_handler : t -> ((packet * string) list -> unit) -> unit
end
