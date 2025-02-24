type t
type daemon

type protocol =
  | ARPv4
  | IPv4
  | IPv6

type 'a packet =
  { src : Macaddr.t option
  ; dst : Macaddr.t
  ; protocol : protocol
  ; payload : 'a }

val write :
     t
  -> ?force:bool
  -> ?src:Macaddr.t
  -> dst:Macaddr.t
  -> protocol:protocol
  -> string
  -> (unit, [> `Exceeds_MTU ]) result
(** [write ?force ?src ~dst ~protocol payload] writes a new ethernet packet with
    the given [payload], [dst] and [protocol]. If the source [src] is not
    specified, the ethernet interface's MAC address is used.

    The [?force] argument (it takes the value [true] by default) signals to
    write this packet in the next cycle of the scheduler. Otherwise, this packet
    is added and will be written at the next {i opportunity} (if someone else
    forces the writing or if we receive a new ethernet packet). *)

val unsafe_write :
     t
  -> ?force:bool
  -> ?src:Macaddr.t
  -> dst:Macaddr.t
  -> protocol:protocol
  -> string
  -> unit

val create :
     ?mtu:int
  -> ?handler:(Bstr.t packet -> unit)
  -> Macaddr.t
  -> Miou_solo5.Net.t
  -> daemon * t

val kill : daemon -> unit
