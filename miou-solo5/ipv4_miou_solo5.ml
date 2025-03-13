let src = Logs.Src.create "ipv4-miou-solo5"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Flag = struct
  type t = DF | MF

  let _dfmf = [ DF; MF ]
  let _df = [ DF ]
  let _mf = [ MF ]
  let _none = []

  let of_int cmd =  match cmd land 0b11 with
    | 0b11 -> _dfmf
    | 0b10 -> _df
    | 0b01 -> _mf
    | _ -> _none

  let to_int flags =
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
    ; opt : Slice_bstr.t }
  and protocol = ICMP | TCP | UDP

  let protocol_of_int = function
    | 1 -> Ok ICMP
    | 6 -> Ok TCP
    | 17 -> Ok UDP
    | n -> error_msgf "Invalid IPv4 protocol (%02x)" n

  let protocol_to_int = function
    | ICMP -> 1
    | TCP -> 6
    | UDP -> 17

  let pp_error ppf = function
    | `Invalid_IPv4_packet -> Fmt.string ppf "bad packet"
    | `Invalid_checksum -> Fmt.string ppf "bad checksum"
    | `Msg msg -> Fmt.string ppf msg

  (*
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
  *)

  let guard err fn = if fn () then Ok () else Error err

  let decode slice =
    let ( let* ) = Result.bind in
    let version_and_ihl = SBstr.get_uint8 slice 0 in
    let ihl = version_and_ihl land 0b1111 in
    let* () = guard `Invalid_IPv4_packet @@ fun () ->
      SBstr.length slice >= 20 in
    let length = SBstr.get_uint16_be slice 2 in
    let uid = SBstr.get_uint16_be slice 4 in
    let flags_and_off = SBstr.get_uint16_be slice 6 in
    let flags = Flag.of_int (flags_and_off lsr 13) in
    let off = flags_and_off land 0x1fff in
    let ttl = SBstr.get_uint8 slice 8 in
    let protocol = SBstr.get_uint8 slice 9 in
    let* protocol = protocol_of_int protocol in
    let checksum = SBstr.get_uint16_be slice 10 in
    let chk =
      let { Slice.buf; off; _ } = slice in
      Bstr.set_uint16_be buf (off + 10) 0;
      Utcp.Checksum.digest ~off ~len:(ihl * 4) buf in
    let* () = guard `Invalid_checksum @@ fun () -> checksum == chk in
    let src = Ipaddr.V4.of_int32 (SBstr.get_int32_be slice 12) in
    let dst = Ipaddr.V4.of_int32 (SBstr.get_int32_be slice 16) in
    let opt =
      if ihl == 5
      then SBstr.empty
      else SBstr.sub slice ~off:20 ~len:((ihl * 4) - 20) in
    let checksum_and_length = { checksum; length } in
    let pkt = { src; dst; uid; flags; off; ttl; protocol; checksum_and_length; opt } in
    let payload = SBstr.shift slice (20 + SBstr.length opt) in
    Ok (pkt, payload)

  let flags_and_off_to_int t =
    let flags = Flag.to_int t.flags in
    (flags lsl 13) lor t.off

  let unsafe_encode_into t ?(off= 0) bstr =
    let version_and_ihl = (4 lsl 4) lor 5 in
    Bstr.set_uint8 bstr (off + 0) version_and_ihl;
    Bstr.set_uint8 bstr (off + 1) 0;
    Bstr.set_uint16_be bstr (off + 2) 0;
    Bstr.set_uint16_be bstr (off + 4) t.uid;
    Bstr.set_uint16_be bstr (off + 6) (flags_and_off_to_int t);
    Bstr.set_uint8 bstr (off + 8) t.ttl;
    Bstr.set_uint8 bstr (off + 9) (protocol_to_int t.protocol);
    Bstr.set_uint16_be bstr (off + 10) 0;
    Bstr.set_int32_be bstr (off + 12) (Ipaddr.V4.to_int32 t.src);
    Bstr.set_int32_be bstr (off + 16) (Ipaddr.V4.to_int32 t.dst)
end

module Fragments = struct
  let src = Logs.Src.create "fragments"
  
  module Log = (val Logs.src_log src : Logs.LOG)

  type elt = { mutable payload : Fragment.t; expire : int }

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

  let catch ~on_exn fn =
    try fn () with exn -> on_exn exn

  let insert t pkt slice =
    let src = pkt.Packet.src
    and dst = pkt.Packet.dst
    and protocol = to_protocol pkt.Packet.protocol
    and uid = pkt.Packet.uid
    and off = pkt.Packet.off * 8
    and limit = not (List.exists ((==) Flag.MF) pkt.Packet.flags) in
    let key = { Fragment.src; dst; protocol; uid } in
    match Table.find t.table key with
    | exception Not_found ->
        clear t;
        if Table.is_full t.table == false
        then
          let now = Miou_solo5.clock_monotonic () in
          let payload = Fragment.singleton ~off ~limit slice in
          Table.add t.table key { payload; expire= now + t.to_expire }
        else Log.warn (fun m -> m "Cache is full, ignore IPv4 packet:%04x" uid)
    | (node, elt) ->
      match elt.payload with
      | Fragment.Payload (Unfragmented _) ->
          Table.remove t.table node
      | Fragment.Payload (Sized _ as p) ->
          let on_exn _exn = Table.remove t.table node in
          catch ~on_exn @@ fun () ->
          let str = SBstr.to_string slice in
          let p = Fragment.insert p ~off ~limit str in
          elt.payload <- Fragment.Payload p
      | Fragment.Payload (Unsized _ as p) ->
          let on_exn _exn = Table.remove t.table node in
          catch ~on_exn @@ fun () ->
          let str = SBstr.to_string slice in
          let p = Fragment.insert p ~off ~limit str in
          elt.payload <- Fragment.Payload p

  type payload =
    | Slice of SBstr.t
    | String of string

  let get t =
    let res = ref [] in
    let fn node =
      let key = Table.key node in
      match Table.value t.table node with
      | None -> ()
      | Some { payload= Fragment.Payload p; _ } ->
          match p with
          | Fragment.Unfragmented slice ->
              res := (key, Slice slice) :: !res;
              Table.remove t.table node
          | Fragment.Sized _ as p ->
              if Fragment.is_complete p
              then begin
                let str = Fragment.reassemble_exn p in
                res := (key, String str) :: !res;
                Table.remove t.table node
              end
          | Fragment.Unsized _ as p ->
              if Fragment.is_complete p
              then begin
                let str = Fragment.reassemble_exn p in
                res := (key, String str) :: !res;
                Table.remove t.table node
              end in
    Table.iter ~fn t.table; !res
end

module Ethernet = Ethernet_miou_solo5
module ARPv4 = Arp_miou_solo5

type packet = Fragment.header =
  { src : Ipaddr.V4.t
  ; dst : Ipaddr.V4.t
  ; protocol : protocol
  ; uid : int }

and protocol = Fragment.protocol = ICMP | TCP | UDP
and payload = Fragments.payload =
  | Slice of SBstr.t
  | String of string

type t =
  { eth : Ethernet.t
  ; arp : ARPv4.t
  ; cidr : Ipaddr.V4.Prefix.t
  ; gateway : Ipaddr.V4.t option
  ; cache : Fragments.t
  ; mutable handler : (packet * payload) list -> unit
  ; src : Logs.src }

module Writer = struct
  type z = |
  type 'a s = |

  type 'a peano =
    | Zero : z peano
    | Succ : 'a peano -> 'a s peano

  [@@@warning "-27"]
  [@@@warning "-37"]

  type ('p, 'q, 'a) m =
    | Bind : ('p, 'q, 'a) m * ('a -> ('q, 'r, 'b) m) -> ('p, 'r, 'b) m
    | Return : 'a -> ('p, 'p, 'a) m
    | Write : ('n s, 'm s, 'a) m * (Bstr.t -> int) -> ('n, 'm s, 'a) m

  type ipv4 = t

  type t =
    | Fixed of { total_length : int; fn : (Bstr.t -> unit) }
      (* invariant: [total_length <= mtu - 20] *)
    | Fragmented of { total_length : int; fn : (Bstr.t -> unit) Seq.t }
      (* invariant: [bstr] is filled to [(mtu - 20) land (lnot 0b111)]
         until the last element (which contains remaining unaligned bytes. *)
    | Unknown : (z, 'n s, unit) m -> t

  let of_string t str =
    let mtu = Ethernet.mtu t.eth in
    let total_length = String.length str in
    if 20 + total_length <= mtu
    then
      let len = total_length in
      let fn = Bstr.blit_from_string str ~src_off:0 ~dst_off:0 ~len in
      Fixed { total_length; fn }
    else
      let fragment = (mtu - 20) land (lnot 0b111) in
      let rec go src_off () =
        if src_off == total_length then Seq.Nil
        else
          let len = Int.min (total_length - src_off) fragment in
          let fn = Bstr.blit_from_string str ~src_off ~dst_off:0 ~len in
          Seq.Cons (fn, go (src_off + len)) in
      Fragmented { total_length; fn= go 0 }

  let chunk chunk_size ?(str_off= 0) sstr =
    let rec go acc str_off chunk_size sstr =
      if chunk_size == 0
      then (List.rev acc, str_off, sstr)
      else match sstr with
        | [] -> (List.rev acc, str_off, sstr)
        | str :: sstr as lst ->
          let len = Int.min chunk_size (String.length str - str_off) in
          let acc = (str, str_off, len) :: acc in
          if str_off + len == String.length str
          then go acc 0 (chunk_size - len) sstr
          else go acc (str_off + len) (chunk_size - len) lst in
    go [] str_off chunk_size sstr

  let of_strings t sstr =
    let mtu = Ethernet.mtu t.eth in
    let total_length =
      let fn acc str = acc + String.length str in
      List.fold_left fn 0 sstr in
    if 20 + total_length <= mtu
    then
      let bufs = Array.of_list sstr in
      let fn bstr =
        let dst_off = ref 0 in
        for i = 0 to Array.length bufs - 1 do
          let str = Array.unsafe_get bufs i in
          let len = String.length str in
          Bstr.blit_from_string str ~src_off:0 bstr ~dst_off:!dst_off ~len;
          dst_off := !dst_off + len
        done in
      Fixed { total_length; fn }
    else
      let fragment = (mtu - 20) land (lnot 0b111) in
      let rec go (str_off, sstr) () = match sstr with
        | [] -> Seq.Nil
        | sstr ->
            let chunk, str_off, sstr = chunk fragment ~str_off sstr in
            let chunk = Array.of_list chunk in
            let fn bstr =
              let dst_off = ref 0 in
              for i = 0 to Array.length chunk - 1 do
                let str, src_off, len = Array.unsafe_get chunk i in
                Bstr.blit_from_string str ~src_off bstr ~dst_off:!dst_off ~len;
                dst_off := !dst_off + len
              done in
            Seq.Cons (fn, go (str_off, sstr)) in
      let fn = go (0, sstr) in
      Fragmented { total_length; fn }

  let into t ~len:total_length fn =
    if 20 + total_length > Ethernet.mtu t.eth
    then invalid_arg "IPv4.Writer.into: too huge IPv4 packet";
    Fixed { total_length; fn }

  let unknown : type n. (z, n s, unit) m -> t = fun m -> Unknown m

  let ( let* ) x fn = Bind (x, fn)
  let ( let+ ) x fn = Write (x, fn)
  let return x = Return x

  type 'a user's_fn =
    | Some : (Bstr.t -> int) -> 'a s user's_fn
    | None : z user's_fn

  type out = (Bstr.t -> int) -> unit

  let rec go : type a p q. out:out -> p peano -> p user's_fn -> (p, q, a) m -> (q peano * q user's_fn * a)
    = fun ~out s user's_fn0 m -> match m, s with
    | Return x, _ -> (s, user's_fn0, x)
    | Bind (m, fn), s ->
        let s, user's_fn1, x = go ~out s user's_fn0 m in
        go ~out s user's_fn1 (fn x)
    | Write (m, user's_fn1), s ->
        let () = match user's_fn0 with None -> ()
          | Some user's_fn0 -> out user's_fn0 in
        go ~out (Succ s) (Some user's_fn1) m
end

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

let max t =
  let mtu = Ethernet.mtu t.eth in
  mtu - 20

let src t = Ipaddr.V4.Prefix.address t.cidr

let fixed pkt user's_fn len bstr =
  Packet.unsafe_encode_into pkt bstr;
  Bstr.set_uint16_be bstr 2 (20 + len);
  let rest = Bstr.sub bstr ~off:20 ~len in
  user's_fn rest;
  let chk = Utcp.Checksum.digest ~off:0 ~len:20 bstr in
  Bstr.set_uint16_be bstr 10 chk;
  20 + len

let write t ?(ttl= 38) ?src dst protocol p =
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
      Logs.debug ~src:t.src (fun m -> m "%a is-at %a" Ipaddr.V4.pp dst Macaddr.pp macaddr);
      let src = Option.value ~default:(Ipaddr.V4.Prefix.address t.cidr) src in
      let mtu = Ethernet.mtu t.eth in
      match p with
      | Writer.Fixed { total_length; fn= user's_fn; } ->
          let pkt =
            { Packet.src; dst; uid= 0; flags= Flag._none; off= 0; ttl
            ; protocol; checksum_and_length= Packet.Partial
            ; opt= SBstr.empty } in
          let protocol = Ethernet.IPv4 in
          let fn = fixed pkt user's_fn total_length in
          Ethernet.write_into t.eth ~dst:macaddr ~protocol fn;
          Ok ()
      | Writer.Fragmented { total_length; fn; } ->
          let uid = Mirage_crypto_rng.generate 2 in
          let uid = String.get_uint16_be uid 0 in
          let rec go off total_length = function
            | Seq.Nil -> ()
            | Seq.Cons (user's_fn, next) ->
                let next = next () in
                let size = Int.min total_length (mtu - 20) in
                let flags =
                  if next != Seq.Nil then Flag._mf else Flag._none in
                let pkt =
                  { Packet.src; dst; uid; flags; off= off lsr 3; ttl; protocol
                  ; checksum_and_length= Packet.Partial; opt= SBstr.empty } in
                let protocol = Ethernet.IPv4 in
                let fn = fixed pkt user's_fn size in
                Ethernet.write_into t.eth ~dst:macaddr ~protocol fn;
                if next != Seq.Nil && total_length - size > 0
                then go (off + size) (total_length - size) next in
          go 0 total_length (fn ());
          Ok ()
      | Unknown m ->
          let uid = Mirage_crypto_rng.generate 2 in
          let uid = String.get_uint16_be uid 0 in
          let off = ref 0 in
          let out ~last user's_fn =
            let fn bstr =
              let flags = if last then Flag._none else Flag._mf in
              let pkt =
                { Packet.src; dst; uid; flags; off= !off lsr 3; ttl
                ; protocol ; checksum_and_length= Packet.Partial
                ; opt= SBstr.empty } in
              Packet.unsafe_encode_into pkt bstr;
              let len = user's_fn (Bstr.sub bstr ~off:20 ~len:(Bstr.length bstr - 20)) in
              Bstr.set_uint16_be bstr 2 (20 + len);
              let len = (len + 0b111) / 8 * 8 in
              off := !off + len;
              let chk = Utcp.Checksum.digest ~off:0 ~len:20 bstr in
              Bstr.set_uint16_be bstr 10 chk;
              20 + len in
            let protocol = Ethernet.IPv4 in
            Ethernet.write_into t.eth ~dst:macaddr ~protocol fn in
          let _, Writer.Some user's_fn, () = Writer.go ~out:(out ~last:false) Writer.Zero Writer.None m in
          out ~last:true user's_fn;
          Ok ()

let input t pkt =
  match Packet.decode pkt.Ethernet.payload with
  | Error err ->
      let str = SBstr.to_string pkt.payload in
      Logs.err ~src:t.src (fun m -> m "Invalid IPv4 packet: %a" Packet.pp_error err);
      Logs.err ~src:t.src (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
  | Ok (ipv4, payload) ->
      let dst = ipv4.Packet.dst in
      if SBstr.length payload > 0
      && (Ipaddr.V4.(compare dst (Prefix.address t.cidr)) == 0
          || Ipaddr.V4.(compare dst Ipaddr.V4.broadcast) == 0
          || Ipaddr.V4.(compare dst (Prefix.broadcast t.cidr)) == 0)
      then begin
        Logs.debug ~src:t.src (fun m -> m "Incoming IPv4 packet from %a"
          Ipaddr.V4.pp ipv4.Packet.src);
        Fragments.insert t.cache ipv4 payload;
        let pkts = Fragments.get t.cache in
        t.handler pkts 
      end

let _cnt = Atomic.make 0

let set_handler t handler =
  Atomic.incr _cnt;
  t.handler <- handler;
  if Atomic.get _cnt > 1
  then Logs.warn ~src:t.src (fun m -> m "IPv4 handler modified more than once")
