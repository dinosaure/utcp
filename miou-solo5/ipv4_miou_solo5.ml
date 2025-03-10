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

  let encode_into pkt ?(off= 0) bstr =
    encode_bstr partial_and_without_options pkt bstr (ref off)
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
    | Packet.Unknown -> invalid_arg "Non-supported protocol"

  let catch ~on_exn fn =
    try fn () with exn -> on_exn exn

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
    | exception Not_found ->
        clear t;
        if Table.is_full t.table == false
        then
          let now = Miou_solo5.clock_monotonic () in
          let payload = Fragment.singleton ~off ~limit str in
          Table.add t.table key { payload; expire= now + t.to_expire }
        else Log.warn (fun m -> m "Cache is full, ignore IPv4 packet:%04x" uid)
    | (node, elt) ->
      match elt.payload with
      | Fragment.Payload (Unfragmented _) ->
          Table.remove t.table node
      | Fragment.Payload (Sized _ as p) ->
          let on_exn _exn = Table.remove t.table node in
          catch ~on_exn @@ fun () ->
          let p = Fragment.insert p ~off ~limit str in
          elt.payload <- Fragment.Payload p
      | Fragment.Payload (Unsized _ as p) ->
          let on_exn _exn = Table.remove t.table node in
          catch ~on_exn @@ fun () ->
          let p = Fragment.insert p ~off ~limit str in
          elt.payload <- Fragment.Payload p

  type payload =
    | Bstr of Bstr.t
    | String of string

  let get t =
    let res = ref [] in
    let fn node =
      let key = Table.key node in
      match Table.value t.table node with
      | None -> ()
      | Some { payload= Fragment.Payload p; _ } ->
          match p with
          | Fragment.Unfragmented bstr ->
              res := (key, Bstr bstr) :: !res;
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

let shift str n =
  let len = String.length str in
  String.sub str n (len - n)

let _split_on ~fragment sstr =
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

type packet = Fragment.header =
  { src : Ipaddr.V4.t
  ; dst : Ipaddr.V4.t
  ; protocol : protocol
  ; uid : int }

and protocol = Fragment.protocol = ICMP | TCP | UDP
and payload = Fragments.payload =
  | Bstr of Bstr.t
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

  type yield = last:bool -> (Bstr.t -> int) -> unit

  let ( let* ) x fn = Bind (x, fn)
  let ( let+ ) x fn = Write (x, fn)
  let return x = Return x

  type ('a, 'b) refl = Refl : ('a, 'a) refl

  let rec refl : type a b. a peano -> b peano -> (a, b) refl option
    = fun a b -> match a, b with
      | Zero, Zero -> Some Refl
      | Succ a, Succ b ->
          begin match refl a b with
          | Some Refl -> Some Refl
          | None -> None end
      | _ -> None

  let rec go : type a p q. yield:yield -> p peano -> (p, q, a) m -> (q peano * a)
    = fun ~yield s m -> match m, s with
    | Return x, _ -> (s, x)
    | Bind (m, fn), s ->
        let s, x = go ~yield s m in
        go ~yield s (fn x)
    | Write (m, user's_fn), s ->
        let s', r = go ~yield (Succ s) m in
        match refl s' (Succ s) with
        | Some Refl -> yield ~last:true user's_fn; s', r
        | None -> yield ~last:false user's_fn; s', r
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
  Packet.encode_into pkt bstr;
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
      let src = Option.value ~default:(Ipaddr.V4.Prefix.address t.cidr) src in
      let mtu = Ethernet.mtu t.eth in
      match p with
      | Writer.Fixed { total_length; fn= user's_fn; } ->
          let pkt =
            { Packet.src; dst; uid= 0; flags= Flag._none; off= 0; ttl
            ; protocol; checksum_and_length= Packet.Partial
            ; opt= Bstr.empty } in
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
                  ; checksum_and_length= Packet.Partial; opt= Bstr.empty } in
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
          let seq =
            let module M = struct
              type _ Effect.t += Yield : { last : bool; user's_fn : (Bstr.t -> int) } -> unit Effect.t
            end in
            let yield ~last user's_fn = Effect.perform (M.Yield { last; user's_fn }) in
            fun () -> match Writer.go ~yield Writer.Zero m with
            | Succ _, () -> Seq.Nil
            | effect M.Yield { last; user's_fn }, k ->
                Seq.Cons ((last, user's_fn), Effect.Deep.continue k) in
          let fn (last, user's_fn) =
            let fn bstr =
              let flags = if last then Flag._none else Flag._mf in
              let pkt =
                { Packet.src; dst; uid; flags; off= !off lsr 3; ttl
                ; protocol ; checksum_and_length= Packet.Partial
                ; opt= Bstr.empty } in
              Packet.encode_into pkt bstr;
              let len = user's_fn (Bstr.sub bstr ~off:20 ~len:(Bstr.length bstr - 20)) in
              Bstr.set_uint16_be bstr 2 (20 + len);
              let len = (len + 0b111) / 8 * 8 in
              off := !off + len;
              let chk = Utcp.Checksum.digest ~off:0 ~len:20 bstr in
              Bstr.set_uint16_be bstr 10 chk;
              20 + len in
            let protocol = Ethernet.IPv4 in
            Ethernet.write_into t.eth ~dst:macaddr ~protocol fn in
          Seq.iter fn seq;
          Ok ()

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
