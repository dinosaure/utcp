module Ethernet = Ethernet_miou_solo5

[@@@warning "-37"]

module Packet = struct
  type t =
    { operation : operation
    ; src_mac : Macaddr.t
    ; dst_mac : Macaddr.t
    ; src_ip : Ipaddr.V4.t
    ; dst_ip : Ipaddr.V4.t }
  and operation =
    | Request | Reply

  open Bin

  let ipaddr = map beint32 Ipaddr.V4.of_int32 Ipaddr.V4.to_int32
  let macaddr = map (bytes 6) Macaddr.of_octets_exn Macaddr.to_octets
  let operation =
    let f = function
      | 1 -> Request
      | 2 -> Reply
      | n -> Fmt.failwith "Invalid ARP operation (%02x)" n in
    let g = function
      | Request -> 1
      | Reply -> 2 in
    map beuint16 f g

  let t =
    let fn _hwtype _ptype _hw_addr_len _p_addr_len
      operation src_mac dst_mac src_ip dst_ip =
        { operation; src_mac; dst_mac; src_ip; dst_ip } in
    record fn
    |+ field beuint16 (Fun.const 1)
    |+ field beuint16 (Fun.const 0x0800)
    |+ field uint8 (Fun.const 6)
    |+ field uint8 (Fun.const 4)
    |+ field operation (fun t -> t.operation)
    |+ field macaddr (fun t -> t.src_mac)
    |+ field macaddr (fun t -> t.dst_mac)
    |+ field ipaddr (fun t -> t.src_ip)
    |+ field ipaddr (fun t -> t.dst_ip)
    |> sealr

  let decode ?(off= 0) bstr =
    try Ok (decode_bstr t bstr (ref off))
    with _exn -> Error `Invalid_ARPv4_packet

  let to_string value = to_string t value
end

let mac0 = Macaddr.of_octets_exn (String.make 6 '\000')

type 'a entry =
  | Static of Macaddr.t * bool
  | Dynamic of Macaddr.t * int
  | Pending of 'a * int

type 'a t =
  { cache : 'a entry Ipaddr.V4.Map.t
  ; macaddr : Macaddr.t
  ; ipaddr : Ipaddr.V4.t
  ; timeout : int
  ; retries : int
  ; epoch : int
  ; src : Logs.src
  ; eth : Ethernet.t }

let pending t ipaddr =
  match Ipaddr.V4.Map.find ipaddr t.cache with
  | exception Not_found -> None
  | Pending (a, _) -> Some a
  | _ -> None

let alias t ipaddr =
  let cache = Ipaddr.V4.Map.add ipaddr (Static (t.macaddr, true)) t.cache in
  let pkt =
    { Packet.operation= Packet.Request
    ; src_mac= t.macaddr
    ; dst_mac= mac0
    ; src_ip= ipaddr
    ; dst_ip= ipaddr } in
  { t with cache }, (pkt, Macaddr.broadcast), pending t ipaddr

let write t (arp, dst) =
  let pkt = Packet.to_string arp in
  (* NOTE(dinosaure): During construction, we verified that we could write ARP
     packets and that we would not exceed the MTU. *)
  Ethernet.unsafe_write t.eth ~dst ~protocol:Ethernet.ARPv4 pkt

let guard err fn = if fn () then Ok () else Error err

let create ?(timeout= 800) ?(retries= 5) ?src ?ipaddr eth =
  let ( let* ) = Result.bind in
  let macaddr = Ethernet.macaddr eth in
  (* enough for ARP packets *)
  let* () = guard `MTU_too_small @@ fun () -> Ethernet.mtu eth >= 28 in
  let src = match src with
    | None -> Logs.Src.create (Fmt.str "%a" Macaddr.pp macaddr)
    | Some src -> src in
  if timeout <= 0
  then Fmt.invalid_arg "Arp_miou_solo5.create: null or negative timeout";
  if retries < 0
  then Fmt.invalid_arg "Arg_miou_solo5.create: negative retries value";
  let unknown = Option.is_none ipaddr in
  let ipaddr = Option.value ~default:Ipaddr.V4.any ipaddr in
  let cache = Ipaddr.V4.Map.empty in
  let t = { cache; macaddr; ipaddr; timeout; retries; epoch= 0; src; eth } in
  let t, out =
    if unknown == false
    then let t, pkt, _ = alias t ipaddr in
         t, Some pkt
    else t, None in
  Option.iter (write t) out; Ok t

let _ips t =
  let fn ip entry acc = match entry with
    | Static (_, true) -> ip :: acc
    | _ -> acc in
  Ipaddr.V4.Map.fold fn t.cache []

let macaddr t = t.macaddr

let _pending t ip =
  match Ipaddr.V4.Map.find ip t.cache with
  | exception Not_found -> None
  | Pending (a, _) -> Some a
  | _ -> None

let request t dst_ip =
  let dst_mac = Macaddr.broadcast in
  { Packet.operation= Request
  ; src_mac= t.macaddr
  ; dst_mac
  ; src_ip= t.ipaddr
  ; dst_ip }, dst_mac

let reply arp macaddr =
  let pkt =
    { Packet.operation= Packet.Reply
    ; src_mac= macaddr
    ; dst_mac= arp.Packet.src_mac
    ; src_ip= arp.Packet.dst_ip
    ; dst_ip= arp.Packet.src_ip } in
  pkt, arp.Packet.src_mac

let tick t =
  let epoch = t.epoch in
  let entry k v (cache, acc, r) = match v with
    | Dynamic (_, tick) when tick == epoch ->
        Ipaddr.V4.Map.remove k cache, acc, r
    | Dynamic (_, tick) when tick == epoch + 1 ->
        cache, request t k :: acc, r
    | Pending (a, retry) when retry == epoch ->
        Ipaddr.V4.Map.remove k cache, acc, a :: r
    | Pending _ -> cache, request t k :: acc, r
    | _ -> cache, acc, r in
  let cache, outs, r = Ipaddr.V4.Map.fold entry t.cache  (t.cache, [], []) in
  List.iter (write t) outs;
  { t with cache; epoch= t.epoch + 1 }, r

let handle_request t arp =
  let dst = arp.Packet.dst_ip in
  let src = arp.Packet.src_ip in
  Logs.debug ~src:t.src (fun m -> m "%a: who has %a?"
    Ipaddr.V4.pp src Ipaddr.V4.pp dst);
  match Ipaddr.V4.Map.find dst t.cache with
  | exception Not_found -> t, None
  | Static (macaddr, true) ->
      write t (reply arp macaddr); t, None
  | _ -> t, None

let handle_reply t src macaddr =
  let t' =
    let entry = Dynamic (macaddr, t.epoch + t.timeout) in
    let cache = Ipaddr.V4.Map.add src entry t.cache in
    { t with cache } in
  Logs.debug ~src:t.src (fun m -> m "handle ARPv4 reply packet from %a:%a"
    Macaddr.pp macaddr Ipaddr.V4.pp src);
  match Ipaddr.V4.Map.find src t.cache with
  | exception Not_found -> t, None
  | Static _ -> t, None
  | Dynamic (macaddr', _) ->
      if Macaddr.compare macaddr macaddr' != 0
      then Logs.debug ~src:t.src (fun m -> m "set %a from %a to %a"
        Ipaddr.V4.pp src Macaddr.pp macaddr' Macaddr.pp macaddr);
      t', None
  | Pending (v, _) -> t', Some (macaddr, v)

let input t pkt =
  match Packet.decode pkt.Ethernet.payload with
  | Error _ ->
      let str = Bstr.to_string pkt.payload in
      Logs.err ~src:t.src (fun m -> m "Invalid ARPv4 packet:");
      Logs.err ~src:t.src (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str);
      t, None
  | Ok arp ->
      if Ipaddr.V4.compare arp.Packet.src_ip arp.Packet.dst_ip == 0
      || arp.Packet.operation == Packet.Reply
      then
        let mac = arp.Packet.src_mac
        and src = arp.Packet.src_ip in
        handle_reply t src mac
      else handle_request t arp
