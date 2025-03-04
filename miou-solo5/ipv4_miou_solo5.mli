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
    -> ?ttl:int
    -> ?src:Ipaddr.V4.t
    -> Ipaddr.V4.t
    -> protocol
    -> ?finally:(string -> string)
    -> ?size:int
    -> string list
    -> (unit, [> `Route_not_found ]) result
  (** [write ?ttl ?src dst protocol ?finally ?size sstr] writes a new IPv4
      packet (fragmented or not) to the specified destination [dst].

      The layer above IPv4 (notably TCP) may require the IPv4 "pseudo-header"
      before generating its own header (notably to calculate a checksum). The
      [finally] function is called with this pseudo-header and must return the
      header of the layer above IPv4. The size of this header must be known in
      advance via the [size] argument. *)

  val input : t -> Bstr.t Ethernet.packet -> unit
  val set_handler : t -> ((packet * string) list -> unit) -> unit
end
