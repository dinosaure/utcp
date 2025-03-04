let src = Logs.Src.create "ipv4-miou-solo5"

module Log = (val Logs.src_log src : Logs.LOG)

module Flag = struct
  type t = DF | MF

  let _dfmf = [ DF; MF ]
  let _df = [ DF ]
  let _mf = [ MF ]
  let _none = []

  let to_flags cmd =  match cmd land 0b11 with
    | 0b11 -> _dfmf
    | 0b10 -> _df
    | 0b01 -> _mf
    | _ -> _none

  let of_flags flags =
    let cmd = ref 0 in
    let fn = function
      | DF -> cmd := !cmd lor 0b10
      | MF -> cmd := !cmd lor 0b01 in
    List.iter fn flags; !cmd
end

module Packet = struct
  type partial = Partial
  type complete = { checksum : int; length : int }

  type 'a packet =
    { src : Ipaddr.V4.t
    ; dst : Ipaddr.V4.t
    ; uid : int
    ; flags : Flag.t list
    ; off : int
    ; ttl : int
    ; protocol : protocol
    ; checksum_and_length : 'a
    ; opt : Bstr.t }
  and protocol = ICMP | TCP | UDP | Unknown
  and 'a status =
    | P : partial status
    | C : complete status

  open Bin

  let protocol =
    let f = function
      | 1 -> ICMP
      | 6 -> TCP
      | 17 -> UDP
      | _ -> Unknown in
    let g = function
      | ICMP -> 1
      | TCP -> 6
      | UDP -> 17
      | Unknown -> Fmt.failwith "Unknown IPv4 protocol" in
    map uint8 f g

  let flag_and_off =
    let f cmd =
      Flag.to_flags (cmd lsr 13), cmd land 0x1fff in
    let g (flags, off) =
      let cmd = Flag.of_flags flags in
      (cmd lsl 13) lor (off land 0x1fff) in
    map beuint16 f g

  let ipaddr = map beint32 Ipaddr.V4.of_int32 Ipaddr.V4.to_int32

  let total_length : type a. a status -> a packet -> int
    = fun status t -> match status with
    | P -> 0 | C -> t.checksum_and_length.length

  let checksum : type a. a status -> a packet -> int
    = fun status t -> match status with
    | P -> 0 | C -> t.checksum_and_length.checksum

  let t : type a. ?ihl:int -> a status -> a packet Bin.t =
    fun ?(ihl= 5) ->
      if (ihl * 4) > 60 || (ihl * 4) < 20
      then Fmt.invalid_arg "Invalid IHL: %02x" ihl;
      let opt = (ihl * 4) - 20 in
      let version_and_ihl = (4 lsl 4) lor ihl in
      (); fun status ->
      let fn version_and_ihl _ total_length uid (flags, off) ttl protocol
        checksum src dst opt : a packet =
        let ihl' = version_and_ihl land 0b1111 in
        if ihl != ihl'
        then Fmt.invalid_arg "The given IHL does not correspond to decoded IHL";
        match status with
        | P ->
            { src; dst; uid; flags; off; ttl; protocol
            ; checksum_and_length= Partial; opt }
        | C ->
            let checksum_and_length =
              { checksum; length= total_length } in
            { src; dst; uid; flags; off; ttl; protocol
            ; checksum_and_length; opt } in
      let zero = Fun.const 0 in
      record fn
      |+ field uint8 (Fun.const version_and_ihl)
      |+ field uint8 zero
      |+ field beuint16 (total_length status)
      |+ field beuint16 (fun t -> t.uid)
      |+ field flag_and_off (fun t -> t.flags, t.off)
      |+ field uint8 (fun t -> t.ttl)
      |+ field protocol (fun t -> t.protocol)
      |+ field beuint16 (checksum status)
      |+ field ipaddr (fun t -> t.src)
      |+ field ipaddr (fun t -> t.dst)
      |+ field (bstr opt) (fun t -> t.opt)
      |> sealr

  let complete_and_without_options = t ~ihl:5 C
  let partial_and_without_options = t ~ihl:5 P

  let decode ?(off= 0) bstr =
    let version_and_ihl = Bstr.get_uint8 bstr off in
    match version_and_ihl land 0b1111 with
    | 5 ->
        let pos = off in
        let off = ref off in
        let pkt = decode_bstr complete_and_without_options bstr off in
        (* TODO(dinosaure): not sure if we just need to compute the checksum
           and compare it with [0x0000] or set the checksum field to [0],
           compute it and compare with what we expect. *)
        Bstr.set_uint16_be bstr (pos + 10) 0;
        let chk = Utcp.Checksum.digest ~off:pos ~len:(!off - pos) bstr in
        if pkt.checksum_and_length.checksum != chk
        then invalid_arg "Invalid IPv4 checksum";
        let payload = Bstr.shift bstr !off in
        pkt, payload
    | ihl ->
        let off = ref off in
        let pkt = decode_bstr (t ~ihl C) bstr off in
        let payload = Bstr.shift bstr !off in
        pkt, payload

  let decode ?off bstr =
    try Ok (decode ?off bstr)
    with _ -> Error `Invalid_IPv4_packet

  let to_bytes : partial packet -> bytes = fun pkt ->
    Bytes.unsafe_of_string (to_string partial_and_without_options pkt)
end

module Fragments = struct
  let src = Logs.Src.create "fragments"
  
  module Log = (val Logs.src_log src : Logs.LOG)

  type elt = { mutable payload : Fragment.payload; expire : int }

  type t =
    { table : elt Table.t
    ; to_expire : int }

  let max_expiration = Int64.to_int (Duration.of_sec 10)

  let create ?max ?(to_expire= max_expiration) () =
    { table= Table.make ?max ()
    ; to_expire }

  let clear t =
    let now = Miou_solo5.clock_monotonic () in
    let fn node = match Table.value t.table node with
      | Some { expire; _ } when expire < now ->
        Table.remove t.table node
      | _ -> () in
    Table.iter ~fn t.table

  let to_protocol = function
    | Packet.ICMP -> Fragment.ICMP
    | Packet.TCP -> Fragment.TCP
    | Packet.UDP -> Fragment.UDP
    | Packet.Unknown -> invalid_arg "Non-supported protocol"

  let insert t pkt bstr =
    let src = pkt.Packet.src
    and dst = pkt.Packet.dst
    and protocol = to_protocol pkt.Packet.protocol
    and uid = pkt.Packet.uid
    and off = pkt.Packet.off * 8
    and limit = not (List.exists ((==) Flag.MF) pkt.Packet.flags) in
    let str = Bstr.to_string bstr in
    let key = { Fragment.src; dst; protocol; uid } in
    match Table.find t.table key with
    | (node, elt) ->
      begin try let payload = Fragment.insert elt.payload ~off ~limit str in
                elt.payload <- payload
      with exn ->
        Log.err (fun m -> m "Corrupted packet [%04x]: %s" uid (Printexc.to_string exn));
        Table.remove t.table node end
    | exception Not_found ->
        clear t;
        if Table.is_full t.table == false
        then
          let now = Miou_solo5.clock_monotonic () in
          let payload = Fragment.singleton ~off ~limit str in
          Table.add t.table key { payload; expire= now + t.to_expire }
        else Log.warn (fun m -> m "Cache is full, ignore IPv4 packet:%04x" uid)

  let get t =
    let res = ref [] in
    let fn node = match Table.value t.table node with
      | Some { payload; _ } when Fragment.is_complete payload ->
          let key = Table.key node in
          res := (key, Fragment.reassemble_exn payload) :: !res;
          Table.remove t.table node
      | _ -> () in
    Table.iter ~fn t.table; !res
end

module Ethernet = Ethernet_miou_solo5
module ARPv4 = Arp_miou_solo5

let shift str n =
  let len = String.length str in
  String.sub str n (len - n)

let split_on ~fragment sstr =
  let total = List.fold_left (fun acc str -> String.length str + acc) 0 sstr in
  let lens = 1 + ((total - 1) / fragment) in
  let bufs = Array.init lens (fun _ -> Bytes.create fragment) in
  let sstr = ref sstr in
  let dst_off = ref 0 in
  let idx = ref 0 in
  while !idx < lens && !sstr != [] do
    let str = List.hd !sstr in
    let len = Int.min (String.length str) (fragment - !dst_off) in
    Bytes.blit_string str 0 bufs.(!idx) !dst_off len;
    if !dst_off + len == fragment
    then begin dst_off := 0; incr idx end
    else dst_off := !dst_off + len;
    if len == String.length str
    then sstr := List.tl !sstr
    else sstr := (shift str len) :: (List.tl !sstr)
  done;
  if !dst_off < fragment
  then bufs.(lens - 1) <- Bytes.sub bufs.(lens - 1) 0 !dst_off;
  Logs.debug (fun m -> m "Fragmentation done");
  Array.to_list bufs |> List.map Bytes.unsafe_to_string

module Static = struct
  type packet = Fragment.t =
    { src : Ipaddr.V4.t
    ; dst : Ipaddr.V4.t
    ; protocol : protocol
    ; uid : int }

  and protocol = Fragment.protocol = ICMP | TCP | UDP

  type t =
    { eth : Ethernet.t
    ; arp : ARPv4.t
    ; cidr : Ipaddr.V4.Prefix.t
    ; gateway : Ipaddr.V4.t option
    ; cache : Fragments.t
    ; mutable handler : (packet * string) list -> unit
    ; src : Logs.src }

  let guard err fn = if fn () then Ok () else Error err

  let create ?cache:max ?to_expire eth arp ?gateway ?(handler= ignore) cidr =
    let src = Logs.Src.create (Ipaddr.V4.Prefix.to_string cidr) in
    let t = { eth; arp; cidr; gateway
            ; cache= Fragments.create ?max ?to_expire ()
            ; handler
            ; src } in
    let ( let* ) = Result.bind in
    let* () = guard `MTU_too_small @@ fun () -> Ethernet.mtu eth >= 20 + 1 in
    Ok t

  let write t ?(ttl= 38) ?src dst protocol ?(finally= Fun.const "") ?(size= 0) sstr =
    let protocol = match protocol with
      | ICMP -> Packet.ICMP
      | TCP -> Packet.TCP
      | UDP -> Packet.UDP in
    Logs.debug ~src:t.src (fun m -> m "Asking where is %a" Ipaddr.V4.pp dst);
    match Routing.destination_macaddr t.cidr t.gateway t.arp dst with
    | Error (`Exn _ | `Timeout | `Clear) ->
        Logs.err ~src:t.src (fun m -> m "no route found for %a" Ipaddr.V4.pp dst);
        Error `Route_not_found
    | Error `Gateway ->
        Logs.debug ~src:t.src (fun m -> m "no gateway specified for writing IPv4 packets");
        Ok ()
    | Ok macaddr ->
        let src = Option.value ~default:(Ipaddr.V4.Prefix.address t.cidr) src in
        let mtu = Ethernet.mtu t.eth in
        let total_length = 
          let payload = List.fold_left (fun acc str -> String.length str + acc) 0 sstr in
          20 (* ipv4 *) + size + payload in
        if total_length <= mtu
        then begin
          Logs.debug ~src:t.src (fun m -> m "write %d byte(s) to %a:%a"
            total_length Ipaddr.V4.pp dst Macaddr.pp macaddr);
          let pkt = { Packet.src; dst; uid= 0; flags= Flag._none; off= 0
                    ; ttl ; protocol; checksum_and_length= Packet.Partial
                    ; opt= Bstr.empty } in
          let pkt = Packet.to_bytes pkt in
          Bytes.set_uint16_be pkt 2 total_length;
          let hdr = finally (Bytes.unsafe_to_string pkt) in
          let chk = Utcp.Checksum.digest_string
            (Bytes.unsafe_to_string pkt) in
          Bytes.set_uint16_be pkt 10 chk;
          Ethernet.unsafe_writev t.eth ~dst:macaddr ~protocol:Ethernet.IPv4
            (Bytes.unsafe_to_string pkt :: hdr :: sstr);
          Ok ()
        end else begin
          let fragment = (mtu - 20) land (lnot 0b111) in
          Logs.debug ~src:t.src (fun m -> m "Fragment to %d byte(s)" fragment);
          let uid = Mirage_crypto_rng.generate 2 in
          let uid = String.get_uint16_be uid 0 in
          let pkt = { Packet.src; dst; uid; flags= Flag._mf; off= 0
                    ; ttl; protocol; checksum_and_length= Packet.Partial
                    ; opt= Bstr.empty } in
          let pkt = Packet.to_bytes pkt in
          Bytes.set_uint16_be pkt 2 (20 + fragment);
          let hdr = finally (Bytes.unsafe_to_string pkt) in
          let[@warning "-8"] first :: payloads = split_on ~fragment (hdr :: sstr) in
          let chk = Utcp.Checksum.digest_string
            (Bytes.unsafe_to_string pkt) in
          Bytes.set_uint16_be pkt 10 chk;
          Ethernet.unsafe_writev t.eth ~dst:macaddr ~protocol:Ethernet.IPv4
            [ Bytes.unsafe_to_string pkt; first ];
          let rec go off = function
            | [] -> Ok ()
            | payload :: rest ->
                let flags = if rest == [] then Flag._none else Flag._mf in
                let pkt = { Packet.src; dst; uid; flags; off= off / 8
                          ; ttl; protocol; checksum_and_length= Packet.Partial
                          ; opt= Bstr.empty } in
                let pkt = Packet.to_bytes pkt in
                Bytes.set_uint16_be pkt 2 (20 + String.length payload);
                let chk = Utcp.Checksum.digest_strings
                  [ Bytes.unsafe_to_string pkt ] in
                Bytes.set_uint16_be pkt 10 chk;
                Ethernet.unsafe_writev t.eth ~dst:macaddr ~protocol:Ethernet.IPv4
                  [ Bytes.unsafe_to_string pkt; payload ];
                go (off + String.length payload) rest in
          go (String.length first) payloads
        end

  let input t pkt =
    match Packet.decode pkt.Ethernet.payload with
    | Error _ ->
        let str = Bstr.to_string pkt.payload in
        Logs.err ~src:t.src (fun m -> m "Invalid IPv4 packet:");
        Logs.err ~src:t.src (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
    | Ok (ipv4, payload) ->
        let dst = ipv4.Packet.dst in
        if Bstr.length payload == 0
        then Logs.debug ~src:t.src (fun m -> m "drop empty IPv4 packet")
        else if ipv4.Packet.protocol == Unknown
        then Logs.debug ~src:t.src (fun m -> m "drop IPv4 packet with unknown protocol")
        else if Ipaddr.V4.(compare dst (Prefix.address t.cidr)) == 0
        || Ipaddr.V4.(compare dst Ipaddr.V4.broadcast) == 0
        || Ipaddr.V4.(compare dst (Prefix.broadcast t.cidr)) == 0
        then begin
          Logs.debug ~src:t.src (fun m -> m "Incoming IPv4 packet from %a"
            Ipaddr.V4.pp ipv4.Packet.src);
          Fragments.insert t.cache ipv4 payload;
          let pkts = Fragments.get t.cache in
          t.handler pkts 
        end else Logs.debug ~src:t.src (fun m -> m "drop IPv4 packet (%a -> %a)"
          Ipaddr.V4.pp ipv4.Packet.src Ipaddr.V4.pp ipv4.Packet.dst)

  let _cnt = Atomic.make 0

  let set_handler t handler =
    Atomic.incr _cnt;
    t.handler <- handler;
    if Atomic.get _cnt > 1
    then Logs.warn ~src:t.src (fun m -> m "IPv4 handler modified more than once")
end
